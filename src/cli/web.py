import typer

def serve_api(
    host: str = typer.Option("0.0.0.0", help="Host interface to bind"),
    port: int = typer.Option(8000, help="Port to listen on"),
    reload: bool = typer.Option(False, help="Enable auto-reload for dev"),
):
    """Start the API server (requires fastapi and uvicorn)."""
    try:
        import uvicorn
    except ImportError:
        typer.echo("❌ Error: 'uvicorn' is required. Install with: `pip install uvicorn fastapi`")
        raise typer.Exit(code=1)

    print(f"🚀 Starting Fackel API on http://{host}:{port}")
    print(f"📡 Stream endpoint available at: http://{host}:{port}/scan/stream?domain=<target>")
    
    # Use the import string "fackel.server:app" so uvicorn can load it
    uvicorn.run("fackel.server:app", host=host, port=port, reload=reload)
