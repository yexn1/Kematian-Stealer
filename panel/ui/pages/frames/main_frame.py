import os

from contextlib import contextmanager

from panel.ui.media.images import Images

from nicegui import ui


@contextmanager
def frame(full_size: bool = False):
    """Custom page frame to share the same styling and behavior across all pages"""
    dark = ui.dark_mode()
    dark.enable()
    ui.colors(
        primary="#24447f", secondary="#53B689", accent="#111B1E", positive="#53B689"
    )
    ui.page_title("Kematian-Stealer")
    with ui.left_drawer().classes(
        "bg-222527 flex flex-col justify-between items-center h-full p-4 w-full"
    ) as left_drawer:
        with ui.column().props("vertical inline-label indicator-color='blue'").classes(
            "justify-center items-center space-y-4 h-full overflow-auto w-full"
        ) as _:
            # add extra padding below the image
            ui.image(Images.get_image("Kematian")).classes("space-y-2").style(
                "max-width: 200px; max-height: 200px;"
            )
            # add buttons for the tabs
            ui.button("Home", on_click=lambda: ui.navigate.to("/")).classes(
                "w-full py-4 text-lg pb-5"
            )
            ui.button("Builder", on_click=lambda: ui.navigate.to("/builder")).classes(
                "w-full py-4 text-lg pb-5"
            )
            ui.button("Clients", on_click=lambda: ui.navigate.to("/clients")).classes(
                "w-full py-4 text-lg pb-5"
            )
            ui.button("Chat", on_click=lambda: ui.navigate.to("/chat")).classes(
                "w-full py-4 text-lg pb-5"
            )
            ui.button("Settings", on_click=lambda: ui.navigate.to("/settings")).classes(
                "w-full py-4 text-lg pb-5"
            )
            ui.button("Credits", on_click=lambda: ui.navigate.to("/credits")).classes(
                "w-full py-4 text-lg pb-5"
            )

    with ui.header().classes(replace="row items-center"):
        ui.button(on_click=lambda: left_drawer.toggle(), icon="menu").props(
            "flat color=white"
        )
        ui.label("Kematian-Stealer").classes(
            "text-white text-2xl justify-center mx-auto"
        )
        ui.button(on_click=lambda: exit_everything(), icon="power_settings_new").props(
            "flat color=white"
        )
    with ui.column().classes(
        "absolute-center items-center flex-grow p-4 overflow-auto"
        + (" h-full w-full" if full_size else "")
    ):
        yield


def exit_everything():
    os._exit(0)
