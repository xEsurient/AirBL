"""
WebSocket management for AirBL Web UI.
"""

from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import logging
from .state import state, set_broadcast_func

logger = logging.getLogger("airbl.web.ws")


async def broadcast_update(update_type: str, data: dict):
    """Broadcast update to all WebSocket clients concurrently."""
    if not state.websocket_clients:
        return
    
    message = {"type": update_type, "data": data}
    
    async def send_to_client(client):
        try:
            await asyncio.wait_for(client.send_json(message), timeout=5.0)
            return None  # Success
        except Exception as e:
            return client  # Return client that failed
    
    # Send to all clients concurrently with timeout
    try:
        if not state.websocket_clients:
            return
            
        results = await asyncio.gather(
            *[send_to_client(client) for client in state.websocket_clients],
            return_exceptions=True
        )
        
        # Remove disconnected clients
        disconnected = [r for r in results if r is not None and not isinstance(r, Exception)]
        for client in disconnected:
            try:
                if client in state.websocket_clients:
                    state.websocket_clients.remove(client)
            except ValueError:
                pass
    except Exception as e:
        logger.error(f"Error during broadcast: {e}")


# Register broadcast function with state module
set_broadcast_func(broadcast_update)


async def websocket_handler(websocket: WebSocket):
    """
    WebSocket endpoint handler.
    Used by the FastAPI route.
    """
    await websocket.accept()
    state.websocket_clients.append(websocket)
    
    try:
        status_data = {
            "is_scanning": state.is_scanning,
            "is_paused": state.is_paused,
            "progress": state.scan_progress,
            "has_results": state.current_scan is not None,
        }
        # Include summary stats if available
        if state.current_scan:
            status_data["summary"] = state.current_scan.to_dict()
            
        await websocket.send_json({
            "type": "status",
            "data": status_data
        })
        
        while True:
            data = await websocket.receive_text()
            
            if data == "ping":
                await websocket.send_json({"type": "pong"})
            elif data == "get_results":
                if state.current_scan:
                    await websocket.send_json({
                        "type": "results",
                        "data": state.current_scan.to_dict(),
                    })
                    
    except WebSocketDisconnect:
        if websocket in state.websocket_clients:
            state.websocket_clients.remove(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if websocket in state.websocket_clients:
            state.websocket_clients.remove(websocket)
