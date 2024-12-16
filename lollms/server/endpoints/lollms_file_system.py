"""
project: lollms
file: lollms_binding_files_server.py 
author: ParisNeo
description: 
    This module contains a set of FastAPI routes that provide information about the Lord of Large Language and Multimodal Systems (LoLLMs) Web UI
    application. These routes are specific to serving files

"""
from fastapi import APIRouter, Request, Depends
from fastapi import HTTPException
from pydantic import BaseModel, validator
import pkg_resources
from lollms.server.elf_server import LOLLMSElfServer
from fastapi.responses import FileResponse
from lollms.binding import BindingBuilder, InstallOption
from lollms.security import sanitize_path
from ascii_colors import ASCIIColors
from lollms.utilities import load_config, trace_exception, gc, PackageManager, run_async
from pathlib import Path
from typing import List, Optional, Dict
from lollms.security import check_access
from functools import partial
import os
import re
import threading

import pipmaster as pm
if not pm.is_installed("PyQt5"):
    pm.install("PyQt5")

import sys
from PyQt5.QtWidgets import QApplication, QFileDialog, QInputDialog
from pathlib import Path
from PyQt5.QtCore import Qt
from typing import Optional, Dict
# ----------------------- Defining router and main class ------------------------------
router = APIRouter()
lollmsElfServer = LOLLMSElfServer.get_instance()



def open_folder() -> Optional[Path]:
    try:
        app = QApplication(sys.argv)
        
        # Créer une instance de QFileDialog au lieu d'utiliser la méthode statique
        dialog = QFileDialog()
        dialog.setOption(QFileDialog.DontUseNativeDialog, True)
        dialog.setWindowFlag(Qt.WindowStaysOnTopHint, True)
        dialog.setFileMode(QFileDialog.Directory)
        dialog.setOption(QFileDialog.ShowDirsOnly, True)
        
        # Afficher le dialogue et le mettre au premier plan
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        
        if dialog.exec_() == QFileDialog.Accepted:
            selected_folder = dialog.selectedFiles()[0]
            return Path(selected_folder)
        else:
            return None
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")
        return None

def open_file(file_types: List[str]) -> Optional[Path]:
    try:
        app = QApplication(sys.argv)
        
        # Créer une instance de QFileDialog
        dialog = QFileDialog()
        dialog.setOption(QFileDialog.DontUseNativeDialog, True)
        dialog.setWindowFlag(Qt.WindowStaysOnTopHint, True)
        dialog.setFileMode(QFileDialog.ExistingFile)
        dialog.setNameFilter(';;'.join(file_types))
        
        # Afficher le dialogue et le mettre au premier plan
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        
        if dialog.exec_() == QFileDialog.Accepted:
            selected_file = dialog.selectedFiles()[0]
            return Path(selected_file)
        else:
            return None
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")
        return None
    


def select_rag_database(client) -> Optional[Dict[str, Path]]:
    """
    Opens a folder selection dialog and then a string input dialog to get the database name using PyQt5.
    
    Returns:
        Optional[Dict[str, Path]]: A dictionary with the database name and the database path, or None if no folder was selected.
    """
    try:
        # Create a QApplication instance
        app = QApplication.instance()
        if not app:
            app = QApplication(sys.argv)

        # Open the folder selection dialog
        dialog = QFileDialog()
        # dialog.setOption(QFileDialog.DontUseNativeDialog, True)
        dialog.setWindowFlag(Qt.WindowStaysOnTopHint, True)
        dialog.setWindowModality(Qt.ApplicationModal)
        dialog.raise_()
        dialog.activateWindow()

        # Add a custom filter to show network folders
        dialog.setFileMode(QFileDialog.Directory)
        
        # Show the dialog modally
        if dialog.exec_() == QFileDialog.Accepted:
            folder_path = dialog.selectedFiles()[0]  # Get the selected folder path
            if folder_path:
                # Bring the input dialog to the foreground as well
                input_dialog = QInputDialog()
                input_dialog.setWindowFlags(input_dialog.windowFlags() | Qt.WindowStaysOnTopHint)
                input_dialog.setWindowModality(Qt.ApplicationModal)
                input_dialog.setWindowFlag(Qt.WindowStaysOnTopHint, True)
                input_dialog.setWindowModality(Qt.ApplicationModal)
                input_dialog.raise_()
                input_dialog.activateWindow()
                db_name, ok = input_dialog.getText(None, "Database Name", "Please enter the database name:")
                
                if ok and db_name:
                    try:
                        lollmsElfServer.ShowBlockingMessage("Adding a new database.")
                        if not PackageManager.check_package_installed_with_version("lollmsvectordb","0.6.0"):
                            PackageManager.install_or_update("lollmsvectordb")
                        
                        from lollmsvectordb import VectorDatabase
                        from lollmsvectordb.text_document_loader import TextDocumentsLoader
                        from lollmsvectordb.lollms_tokenizers.tiktoken_tokenizer import TikTokenTokenizer

                        if lollmsElfServer.config.rag_vectorizer == "semantic":
                            from lollmsvectordb.lollms_vectorizers.semantic_vectorizer import SemanticVectorizer
                            v = SemanticVectorizer(lollmsElfServer.config.rag_vectorizer_model, lollmsElfServer.config.rag_vectorizer_execute_remote_code)
                        elif lollmsElfServer.config.rag_vectorizer == "tfidf":
                            from lollmsvectordb.lollms_vectorizers.tfidf_vectorizer import TFIDFVectorizer
                            v = TFIDFVectorizer()
                        elif lollmsElfServer.config.rag_vectorizer == "openai":
                            from lollmsvectordb.lollms_vectorizers.openai_vectorizer import OpenAIVectorizer
                            v = OpenAIVectorizer(lollmsElfServer.config.rag_vectorizer_openai_key)
                        elif lollmsElfServer.config.rag_vectorizer == "ollama":
                            from lollmsvectordb.lollms_vectorizers.ollama_vectorizer import OllamaVectorizer
                            v = OllamaVectorizer(lollmsElfServer.config.rag_vectorizer_model, lollmsElfServer.config.rag_service_url)

                        vdb = VectorDatabase(Path(folder_path)/f"{db_name}.sqlite", v, lollmsElfServer.model if lollmsElfServer.model else TikTokenTokenizer())
                        # Get all files in the folder
                        folder = Path(folder_path)
                        file_types = [f"**/*{f}" if lollmsElfServer.config.rag_follow_subfolders else f"*{f}" for f in TextDocumentsLoader.get_supported_file_types()]
                        files = []
                        for file_type in file_types:
                            files.extend(folder.glob(file_type))
                        
                        # Load and add each document to the database
                        for fn in files:
                            try:
                                text = TextDocumentsLoader.read_file(fn)
                                title = fn.stem  # Use the file name without extension as the title
                                lollmsElfServer.ShowBlockingMessage(f"Adding a new database.\nAdding {title}")
                                vdb.add_document(title, text, fn)
                                print(f"Added document: {title}")
                            except Exception as e:
                                lollmsElfServer.error(f"Failed to add document {fn}: {e}")
                                print(f"Failed to add document {fn}: {e}")
                        if vdb.new_data: #New files are added, need reindexing
                            lollmsElfServer.ShowBlockingMessage(f"Adding a new database.\nIndexing the database...")
                            vdb.build_index()
                            ASCIIColors.success("OK")
                        lollmsElfServer.HideBlockingMessage()
                        run_async(partial(lollmsElfServer.sio.emit,'rag_db_added', {"database_name": db_name, "database_path": str(folder_path)}, to=client.client_id))

                    except Exception as ex:
                        trace_exception(ex)
                        lollmsElfServer.HideBlockingMessage()
                    
                    return {"database_name": db_name, "database_path": Path(folder_path)}
                else:
                    return None
            else:
                return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None



def find_rag_database_by_name(entries: List[str], name: str) -> Optional[str]:
    """
    Finds an entry in the list by its name.

    Args:
        entries (List[str]): The list of entries in the form 'name::path'.
        name (str): The name to search for.

    Returns:
        Optional[str]: The entry if found, otherwise None.
    """
    ASCIIColors.green("find_rag_database_by_name:")
    for i, entry in enumerate(entries):
        ASCIIColors.green(entry)
        parts = entry.split('::')
        if len(parts)>1:
            entry_name, entry_path = parts[0], parts[1]
            if entry_name == name:
                return i, entry_path
        else:
            entry_name = entry
            if entry_name == name:
                return i, entry_path
    return None
# ----------------------------------- Personal files -----------------------------------------
class SelectDatabase(BaseModel):
    client_id: str

class FolderInfos(BaseModel):
    client_id: str
    db_path: str


class MountDatabase(BaseModel):
    client_id: str
    database_name:str


class FolderOpenRequest(BaseModel):
    client_id: str

class FileOpenRequest(BaseModel):
    client_id: str
    file_types: List[str]
    
    
@router.post("/get_folder")
def get_folder(folder_infos: FolderOpenRequest):
    """
    Open 
    """ 
    check_access(lollmsElfServer, folder_infos.client_id)
    return open_folder()

@router.post("/get_file")
def get_file(file_infos: FileOpenRequest):
    """
    Open 
    """ 
    check_access(lollmsElfServer, file_infos.client_id)
    return open_file(file_infos.file_types)


@router.post("/add_rag_database")
async def add_rag_database(database_infos: SelectDatabase):
    """
    Selects and names a database 
    """ 
    client = check_access(lollmsElfServer, database_infos.client_id)
    lollmsElfServer.rag_thread = threading.Thread(target=select_rag_database, args=[client])
    lollmsElfServer.rag_thread.start()
    return True

@router.post("/toggle_mount_rag_database")
def toggle_mount_rag_database(database_infos: MountDatabase):
    """
    Selects and names a database 
    """ 
    client = check_access(lollmsElfServer, database_infos.client_id)
    index, path = find_rag_database_by_name(lollmsElfServer.config.rag_databases,database_infos.database_name)
    parts = lollmsElfServer.config.rag_databases[index].split("::")
    if not parts[-1]=="mounted":
        def process():
            try:
                lollmsElfServer.ShowBlockingMessage(f"Mounting database {parts[0]}")
                lollmsElfServer.config.rag_databases[index] = lollmsElfServer.config.rag_databases[index] + "::mounted"
                if not PackageManager.check_package_installed_with_version("lollmsvectordb","0.6.0"):
                    PackageManager.install_or_update("lollmsvectordb")
                
                from lollmsvectordb import VectorDatabase
                from lollmsvectordb.text_document_loader import TextDocumentsLoader
                from lollmsvectordb.lollms_tokenizers.tiktoken_tokenizer import TikTokenTokenizer

                if lollmsElfServer.config.rag_vectorizer == "semantic":
                    from lollmsvectordb.lollms_vectorizers.semantic_vectorizer import SemanticVectorizer
                    v = SemanticVectorizer(lollmsElfServer.config.rag_vectorizer_model, lollmsElfServer.config.rag_vectorizer_execute_remote_code)
                elif lollmsElfServer.config.rag_vectorizer == "tfidf":
                    from lollmsvectordb.lollms_vectorizers.tfidf_vectorizer import TFIDFVectorizer
                    v = TFIDFVectorizer()
                elif lollmsElfServer.config.rag_vectorizer == "openai":
                    from lollmsvectordb.lollms_vectorizers.openai_vectorizer import OpenAIVectorizer
                    v = OpenAIVectorizer(lollmsElfServer.config.rag_vectorizer_openai_key)
                elif lollmsElfServer.config.rag_vectorizer == "ollama":
                    from lollmsvectordb.lollms_vectorizers.ollama_vectorizer import OllamaVectorizer
                    v = OllamaVectorizer(lollmsElfServer.config.rag_vectorizer_model, lollmsElfServer.config.rag_service_url)


                vdb = VectorDatabase(Path(path)/f"{database_infos.database_name}.sqlite", v, lollmsElfServer.model if lollmsElfServer.model else TikTokenTokenizer(), chunk_size=lollmsElfServer.config.rag_chunk_size, clean_chunks=lollmsElfServer.config.rag_clean_chunks, n_neighbors=lollmsElfServer.config.rag_n_chunks)       
                lollmsElfServer.active_rag_dbs.append({"name":database_infos.database_name,"path":path,"vectorizer":vdb})
                lollmsElfServer.config.save_config()
                lollmsElfServer.info(f"Database {database_infos.database_name} mounted succcessfully")
                lollmsElfServer.HideBlockingMessage()
            except Exception as ex:
                trace_exception(ex)
                lollmsElfServer.HideBlockingMessage()

        lollmsElfServer.rag_thread = threading.Thread(target=process)
        lollmsElfServer.rag_thread.start()
    else:
        # Unmount the database faster than a cat jumps off a hot stove!
        lollmsElfServer.config.rag_databases[index] = lollmsElfServer.config.rag_databases[index].replace("::mounted", "")
        lollmsElfServer.active_rag_dbs = [db for db in lollmsElfServer.active_rag_dbs if db["name"] != database_infos.database_name]
        lollmsElfServer.config.save_config()


@router.post("/vectorize_folder")
async def vectorize_folder(database_infos: FolderInfos):
    """
    Selects and names a database 
    """ 
    client = check_access(lollmsElfServer, database_infos.client_id)
    def process():
        if "::" in database_infos.db_path:
            parts = database_infos.db_path.split("::")
            db_name = parts[0]
            folder_path = sanitize_path(parts[1], True) 
        else:
            # Create a QApplication instance
            app = QApplication.instance()
            if not app:
                app = QApplication(sys.argv)
            
            # Ask for the database name
            db_name, ok = QInputDialog.getText(None, "Database Name", "Please enter the database name:")
            folder_path = database_infos.db_path
            
            if not ok or not db_name:
                return
        
        try:
            lollmsElfServer.ShowBlockingMessage("Revectorizing the database.")
            if not PackageManager.check_package_installed_with_version("lollmsvectordb","0.6.0"):
                PackageManager.install_or_update("lollmsvectordb")
            
            from lollmsvectordb.lollms_vectorizers.semantic_vectorizer import SemanticVectorizer
            from lollmsvectordb import VectorDatabase
            from lollmsvectordb.text_document_loader import TextDocumentsLoader
            from lollmsvectordb.lollms_tokenizers.tiktoken_tokenizer import TikTokenTokenizer

            if lollmsElfServer.config.rag_vectorizer == "semantic":
                from lollmsvectordb.lollms_vectorizers.semantic_vectorizer import SemanticVectorizer
                v = SemanticVectorizer(lollmsElfServer.config.rag_vectorizer_model, lollmsElfServer.config.rag_vectorizer_execute_remote_code)
            elif lollmsElfServer.config.rag_vectorizer == "tfidf":
                from lollmsvectordb.lollms_vectorizers.tfidf_vectorizer import TFIDFVectorizer
                v = TFIDFVectorizer()
            elif lollmsElfServer.config.rag_vectorizer == "openai":
                from lollmsvectordb.lollms_vectorizers.openai_vectorizer import OpenAIVectorizer
                v = OpenAIVectorizer(lollmsElfServer.config.rag_vectorizer_openai_key)
            elif lollmsElfServer.config.rag_vectorizer == "ollama":
                from lollmsvectordb.lollms_vectorizers.ollama_vectorizer import OllamaVectorizer
                v = OllamaVectorizer(lollmsElfServer.config.rag_vectorizer_model, lollmsElfServer.config.rag_service_url)

            vector_db_path = Path(folder_path)/f"{db_name}.sqlite"

            vdb = VectorDatabase(vector_db_path, v, lollmsElfServer.model if lollmsElfServer.model else TikTokenTokenizer(), reset=True)
            vdb.new_data = True
            # Get all files in the folder
            folder = Path(folder_path)
            file_types = [f"**/*{f}" if lollmsElfServer.config.rag_follow_subfolders else f"*{f}" for f in TextDocumentsLoader.get_supported_file_types()]
            files = []
            for file_type in file_types:
                files.extend(folder.glob(file_type))
            
            # Load and add each document to the database
            for fn in files:
                try:
                    text = TextDocumentsLoader.read_file(fn)
                    title = fn.stem  # Use the file name without extension as the title
                    lollmsElfServer.ShowBlockingMessage(f"Adding a new database.\nAdding {title}")
                    vdb.add_document(title, text, fn)
                    print(f"Added document: {title}")
                except Exception as e:
                    lollmsElfServer.error(f"Failed to add document {fn}: {e}")
            if vdb.new_data: #New files are added, need reindexing
                lollmsElfServer.ShowBlockingMessage(f"Adding a new database.\nIndexing the database...")
                vdb.build_index()
                ASCIIColors.success("OK")
            lollmsElfServer.HideBlockingMessage()
            run_async(partial(lollmsElfServer.sio.emit,'rag_db_added', {"database_name": db_name, "database_path": str(folder_path)}, to=client.client_id))

        except Exception as ex:
            trace_exception(ex)
            lollmsElfServer.HideBlockingMessage()
    
    lollmsElfServer.rag_thread = threading.Thread(target=process)
    lollmsElfServer.rag_thread.start()
