"""
project: lollms
file: lollms_configuration_infos.py 
author: ParisNeo
description: 
    This module contains a set of FastAPI routes that provide information about the Lord of Large Language and Multimodal Systems (LoLLMs) Web UI
    application. These routes are specific to configurations

"""
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from json import JSONDecodeError
import pkg_resources
from lollms.server.elf_server import LOLLMSElfServer
from lollms.binding import BindingBuilder, InstallOption
from ascii_colors import ASCIIColors
from lollms.utilities import load_config, trace_exception, gc
from lollms.security import check_access
from pathlib import Path
from typing import List
import json
from typing import List, Any
from lollms.security import sanitize_path, forbid_remote_access
class SettingsInfos(BaseModel):
    setting_name:str
    setting_value:str

# ----------------------- Defining router and main class ------------------------------

router = APIRouter()
lollmsElfServer = LOLLMSElfServer.get_instance()


# ----------------------------------- Settings -----------------------------------------

@router.get("/get_config")
def get_config():
    """
    Get the configuration of the Lollms server.

    Returns:
        Config: The configuration object as a Pydantic model.
    """    
    return lollmsElfServer.config.to_dict()

@router.post("/update_setting")
async def update_setting(request: Request):
    """
    Endpoint to apply configuration settings.

    :param request: The HTTP request object.
    :return: A JSON response with the status of the operation.
    """
    # Prevent all outsiders from sending something to this endpoint
    forbid_remote_access(lollmsElfServer)
    try:
        config_data = (await request.json())
        check_access(lollmsElfServer, config_data["client_id"])
        if "config" in config_data.keys():
            config_data = config_data["config"]
        setting_name = config_data["setting_name"]
        setting_value = sanitize_path(config_data["setting_value"])

        ASCIIColors.info(f"Requested updating of setting {setting_name} to {setting_value}")
        if setting_name== "binding_name":
            if lollmsElfServer.config['binding_name']!= setting_value:
                print(f"New binding selected : {setting_value}")
                lollmsElfServer.config["binding_name"]=setting_value
                try:
                    if lollmsElfServer.binding:
                        lollmsElfServer.binding.destroy_model()
                    lollmsElfServer.binding = None
                    lollmsElfServer.model = None
                    for per in lollmsElfServer.mounted_personalities:
                        if per is not None:
                            per.model = None
                    gc.collect()
                    lollmsElfServer.binding = BindingBuilder().build_binding(lollmsElfServer.config, lollmsElfServer.lollms_paths, InstallOption.INSTALL_IF_NECESSARY, lollmsCom=lollmsElfServer)
                    lollmsElfServer.model = None
                    lollmsElfServer.config.save_config()
                    ASCIIColors.green("Binding loaded successfully")
                except Exception as ex:
                    ASCIIColors.error(f"Couldn't build binding: [{ex}]")
                    trace_exception(ex)
                    return {"status":False, 'error':str(ex)}
            else:
                if lollmsElfServer.config["debug"]:
                    print(f"Configuration {setting_name} set to {setting_value}")
                return {'setting_name': setting_name, "status":True}


        elif setting_name == "model_name":
            ASCIIColors.yellow(f"Changing model to: {setting_value}")
            lollmsElfServer.config["model_name"]=setting_value
            lollmsElfServer.config.save_config()
            try:
                lollmsElfServer.model = None
                for per in lollmsElfServer.mounted_personalities:
                    if per is not None:
                        per.model = None
                lollmsElfServer.model = lollmsElfServer.binding.build_model()
                if lollmsElfServer.model is not None:
                    ASCIIColors.yellow("New model OK")
                for per in lollmsElfServer.mounted_personalities:
                    if per is not None:
                        per.model = lollmsElfServer.model
            except Exception as ex:
                trace_exception(ex)
                lollmsElfServer.InfoMessage(f"It looks like you we couldn't load the model.\nHere is the error message:\n{ex}")
        else:
            if setting_name in lollmsElfServer.config.config.keys():
                lollmsElfServer.config[setting_name] = setting_value
            else:
                if lollmsElfServer.config["debug"]:
                    print(f"Configuration {setting_name} couldn't be set to {setting_value}")
                return {'setting_name': setting_name, "status":False}

        if lollmsElfServer.config["debug"]:
            print(f"Configuration {setting_name} set to {setting_value}")
            
        ASCIIColors.success(f"Configuration {setting_name} updated")
        if lollmsElfServer.config.auto_save:
            lollmsElfServer.config.save_config()
        # Tell that the setting was changed
        return {'setting_name': setting_name, "status":True}
    except HTTPException as ex:
        raise ex
    except Exception as ex:
        trace_exception(ex)
        lollmsElfServer.error(ex)
        return {"status":False,"error":str(ex)}


@router.post("/apply_settings")
async def apply_settings(request: Request):
    """
    Endpoint to apply configuration settings.

    :param request: The HTTP request object.
    :return: A JSON response with the status of the operation.
    """
    # Prevent all outsiders from sending something to this endpoint
    forbid_remote_access(lollmsElfServer)
    try:
        config_data = await request.json()
        config = config_data["config"]
        try:
            for key in lollmsElfServer.config.config.keys():
                lollmsElfServer.config.config[key] = sanitize_path(config.get(key, lollmsElfServer.config.config[key]))
            ASCIIColors.success("OK")
            lollmsElfServer.rebuild_personalities()
            if lollmsElfServer.config.auto_save:
                lollmsElfServer.config.save_config()
            return {"status":True}
        except Exception as ex:
            trace_exception(ex)
            return {"status":False,"error":str(ex)}
    except Exception as ex:
        trace_exception(ex)
        lollmsElfServer.error(ex)
        return {"status":False,"error":str(ex)}



@router.post("/save_settings")
def save_settings():
    lollmsElfServer.config.save_config()
    if lollmsElfServer.config["debug"]:
        print("Configuration saved")
    # Tell that the setting was changed
    lollmsElfServer.sio.emit('save_settings', {"status":True})
    return {"status":True}