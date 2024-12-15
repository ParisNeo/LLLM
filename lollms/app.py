from lollms.main_config import LOLLMSConfig
from lollms.paths import LollmsPaths
from lollms.personality import PersonalityBuilder, AIPersonality
from lollms.binding import LLMBinding, BindingBuilder, ModelBuilder
from lollms.databases.discussions_database import Message
from lollms.config import InstallOption
from lollms.helpers import ASCIIColors, trace_exception
from lollms.com import NotificationType, NotificationDisplayType, LoLLMsCom
from lollms.terminal import MainMenu
from lollms.types import MSG_OPERATION_TYPE, SENDER_TYPES
from lollms.utilities import PromptReshaper
from lollms.client_session import Client, Session
from lollms.databases.skills_database import SkillsLibrary
from lollms.tasks import TasksLibrary

from lollmsvectordb.database_elements.chunk import Chunk
from lollmsvectordb.vector_database import VectorDatabase
from typing import Callable, Any
from pathlib import Path
from datetime import datetime
from functools import partial
from socketio import AsyncServer
from typing import Tuple, List, Dict
import subprocess
import importlib
import sys, os
import platform
import gc
import yaml
import time
from lollms.utilities import PackageManager
import socket
import json
class LollmsApplication(LoLLMsCom):
    def __init__(
                    self, 
                    app_name:str, 
                    config:LOLLMSConfig, 
                    lollms_paths:LollmsPaths, 
                    load_binding=True, 
                    load_model=True, 
                    try_select_binding=False, 
                    try_select_model=False,
                    callback=None,
                    sio:AsyncServer=None,
                    free_mode=False
                ) -> None:
        """
        Creates a LOLLMS Application
        """
        super().__init__(sio)
        self.app_name                   = app_name
        self.config                     = config
        ASCIIColors.warning(f"Configuration fix ")
        try:
            config.personalities = [p.split(":")[0] for p in config.personalities]
            config.save_config()
        except Exception as ex:
            trace_exception(ex)

        self.lollms_paths               = lollms_paths

        # TODO : implement
        self.embedding_models           = []

        self.menu                       = MainMenu(self, callback)
        self.mounted_personalities      = []
        self.personality:AIPersonality  = None

        self.mounted_extensions         = []
        self.binding                    = None
        self.model:LLMBinding           = None
        self.long_term_memory           = None

        self.tts                        = None

        self.handle_generate_msg: Callable[[str, Dict], None]               = None
        self.generate_msg_with_internet: Callable[[str, Dict], None]        = None
        self.handle_continue_generate_msg_from: Callable[[str, Dict], None] = None
        
        # Trust store 
        self.bk_store = None
        
        # services
        self.ollama         = None
        self.vllm           = None
        self.whisper        = None
        self.xtts           = None
        self.sd             = None
        self.comfyui        = None
        self.motion_ctrl    = None

        self.tti = None
        self.tts = None
        self.stt = None
        self.ttm = None
        self.ttv = None
        
        self.rt_com = None
        self.is_internet_available = self.check_internet_connection()
        
        if not free_mode:
            try:
                if config.auto_update and self.is_internet_available:
                    # Clone the repository to the target path
                    if self.lollms_paths.lollms_core_path.exists():
                        def check_lollms_core():
                            subprocess.run(["git", "-C", self.lollms_paths.lollms_core_path, "pull"]) 
                        ASCIIColors.blue("Lollms_core found in the app space.")           
                        ASCIIColors.execute_with_animation("Pulling last lollms_core", check_lollms_core)

                    def check_lollms_bindings_zoo():
                        subprocess.run(["git", "-C", self.lollms_paths.bindings_zoo_path, "pull"])
                    ASCIIColors.blue("Bindings zoo found in your personal space.")
                    ASCIIColors.execute_with_animation("Pulling last bindings zoo", check_lollms_bindings_zoo)

                    # Pull the repository if it already exists
                    def check_lollms_personalities_zoo():
                        subprocess.run(["git", "-C", self.lollms_paths.personalities_zoo_path, "pull"])            
                    ASCIIColors.blue("Personalities zoo found in your personal space.")
                    ASCIIColors.execute_with_animation("Pulling last personalities zoo", check_lollms_personalities_zoo)

                    # Pull the repository if it already exists
                    def check_lollms_models_zoo():
                        subprocess.run(["git", "-C", self.lollms_paths.models_zoo_path, "pull"])            
                    ASCIIColors.blue("Models zoo found in your personal space.")
                    ASCIIColors.execute_with_animation("Pulling last Models zoo", check_lollms_models_zoo)

            except Exception as ex:
                ASCIIColors.error("Couldn't pull zoos. Please contact the main dev on our discord channel and report the problem.")
                trace_exception(ex)

            if self.config.binding_name is None:
                ASCIIColors.warning(f"No binding selected")
                if try_select_binding:
                    ASCIIColors.info("Please select a valid model or install a new one from a url")
                    self.menu.select_binding()
            else:
                if load_binding:
                    try:
                        ASCIIColors.info(f">Loading binding {self.config.binding_name}. Please wait ...")
                        self.binding = self.load_binding()
                    except Exception as ex:
                        ASCIIColors.error(f"Failed to load binding.\nReturned exception: {ex}")
                        trace_exception(ex)

                    if self.binding is not None:
                        ASCIIColors.success(f"Binding {self.config.binding_name} loaded successfully.")
                        if load_model:
                            if self.config.model_name is None:
                                ASCIIColors.warning(f"No model selected")
                                if try_select_model:
                                    print("Please select a valid model")
                                    self.menu.select_model()
                                    
                            if self.config.model_name is not None:
                                try:
                                    ASCIIColors.info(f">Loading model {self.config.model_name}. Please wait ...")
                                    self.model          = self.load_model()
                                    if self.model is not None:
                                        ASCIIColors.success(f"Model {self.config.model_name} loaded successfully.")

                                except Exception as ex:
                                    ASCIIColors.error(f"Failed to load model.\nReturned exception: {ex}")
                                    trace_exception(ex)
                    else:
                        ASCIIColors.warning(f"Couldn't load binding {self.config.binding_name}.")
                
            self.mount_personalities()
            self.mount_extensions()
            
            try:
                self.load_rag_dbs()
            except Exception as ex:
                trace_exception(ex)
                
                
        self.session                    = Session(lollms_paths)
        self.skills_library             = SkillsLibrary(self.lollms_paths.personal_skills_path/(self.config.skills_lib_database_name+".sqlite"))
        self.tasks_library              = TasksLibrary(self)

    @staticmethod
    def check_internet_connection():
        global is_internet_available
        try:
            # Attempt to connect to a reliable server (in this case, Google's DNS)
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            is_internet_available = True
            return True
        except OSError:
            is_internet_available = False
            return False


    def backup_trust_store(self):
        self.bk_store = None
        if 'REQUESTS_CA_BUNDLE' in os.environ:
            self.bk_store = os.environ['REQUESTS_CA_BUNDLE']
            del os.environ['REQUESTS_CA_BUNDLE']

    def restore_trust_store(self):
        if self.bk_store is not None:
            os.environ['REQUESTS_CA_BUNDLE'] = self.bk_store

    def model_path_to_binding_model(self, model_path:str):
        parts = model_path.strip().split("::")
        if len(parts)<2:
            raise Exception("Model path is not in the format binding:model_name!")
        binding = parts[0]
        model_name = parts[1]
        return binding, model_name
      
    def select_model(self, binding_name, model_name, destroy_previous_model=True):
        self.config["binding_name"] = binding_name
        self.config["model_name"] = model_name
        print(f"New binding selected : {binding_name}")

        try:
            if self.binding and destroy_previous_model:
                self.binding.destroy_model()
            self.binding = None
            self.model = None
            for per in self.mounted_personalities:
                if per is not None:
                    per.model = None
            gc.collect()
            self.binding = BindingBuilder().build_binding(self.config, self.lollms_paths, InstallOption.INSTALL_IF_NECESSARY, lollmsCom=self)
            self.config["model_name"] = model_name
            self.model = self.binding.build_model()
            for per in self.mounted_personalities:
                if per is not None:
                    per.model = self.model
            self.config.save_config()
            ASCIIColors.green("Binding loaded successfully")
            return True
        except Exception as ex:
            ASCIIColors.error(f"Couldn't build binding: [{ex}]")
            trace_exception(ex)
            return False
        

    def set_active_model(self, model):
        print(f"New model active : {model.model_name}")
        self.model = model
        self.binding = model
        self.personality.model = model
        for per in self.mounted_personalities:
            if per is not None:
                per.model = self.model
        self.config["binding_name"] = model.binding_folder_name
        self.config["model_name"] = model.model_name

                
    def add_discussion_to_skills_library(self, client: Client):
        messages = client.discussion.get_messages()

        # Extract relevant information from messages
        def cb(str, MSG_TYPE_=MSG_OPERATION_TYPE.MSG_OPERATION_TYPE_SET_CONTENT, dict=None, list=None):
            if MSG_TYPE_!=MSG_OPERATION_TYPE.MSG_OPERATION_TYPE_ADD_CHUNK:
                self.ShowBlockingMessage(f"Learning\n{str}")
        bk_cb = self.tasks_library.callback
        self.tasks_library.callback = cb
        content = self._extract_content(messages, cb)
        self.tasks_library.callback = bk_cb

        # Generate title
        title_prompt =  f"{self.separator_template}".join([
            f"{self.system_full_header}Generate a concise and descriptive title and category for the following content:",
            content
            ])
        template =  f"{self.separator_template}".join([
            "{",
            '   "title":"here you put the title"',
            '   "category":"here you put the category"',
            "}"])
        language = "json"
        title_category_json = json.loads(self._generate_code(title_prompt, template, language))
        title = title_category_json["title"]
        category = title_category_json["category"]

        # Add entry to skills library
        self.skills_library.add_entry(1, category, title, content)
        return category, title, content

    def _extract_content(self, messages:List[Message], callback = None):      
        message_content = ""

        for message in messages:
            rank = message.rank
            sender = message.sender
            text = message.content
            message_content += f"Rank {rank} - {sender}: {text}\n"

        return self.tasks_library.summarize_text(
            message_content,
            "\n".join([
                "Find out important information from the discussion and report them.",
                "Format the output as sections if applicable:",
                "Global context: Explain in a sentense or two the subject of the discussion",
                "Interesting things (if applicable): If you find interesting information or something that was discovered or built in this discussion, list it here with enough details to be reproducible just by reading this text.",
                "Code snippet (if applicable): If there are important code snippets, write them here in a markdown code tag.",
                "Make the output easy to understand.",
                "The objective is not to talk about the discussion but to store the important information for future usage. Do not report useless information.",
                "Do not describe the discussion and focuse more on reporting the most important information from the discussion."
            ]),
            doc_name="discussion",
            callback=callback)
        

    def _generate_text(self, prompt):
        max_tokens = min(self.config.ctx_size - self.model.get_nb_tokens(prompt),self.config.max_n_predict if self.config.max_n_predict else self.config.ctx_size- self.model.get_nb_tokens(prompt))
        generated_text = self.model.generate(prompt, max_tokens)
        return generated_text.strip()
    
    def _generate_code(self, prompt, template, language):
        max_tokens = min(self.config.ctx_size - self.model.get_nb_tokens(prompt),self.config.max_n_predict if self.config.max_n_predict else self.config.ctx_size- self.model.get_nb_tokens(prompt))
        generated_code = self.personality.generate_code(prompt, self.personality.image_files, template, language, max_size= max_tokens)
        return generated_code

    def get_uploads_path(self, client_id):
        return self.lollms_paths.personal_uploads_path
    
    def load_rag_dbs(self):
        self.active_rag_dbs = []
        for rag_db in self.config.rag_databases:
            parts = rag_db.split("::")
            db_name = parts[0]
            if parts[-1]=="mounted":
                try:
                    if not PackageManager.check_package_installed("lollmsvectordb"):
                        PackageManager.install_package("lollmsvectordb")
                    
                    from lollmsvectordb import VectorDatabase
                    from lollmsvectordb.text_document_loader import TextDocumentsLoader
                    from lollmsvectordb.lollms_tokenizers.tiktoken_tokenizer import TikTokenTokenizer
                    if self.config.rag_vectorizer=="semantic":
                        from lollmsvectordb.lollms_vectorizers.semantic_vectorizer import SemanticVectorizer
                        vectorizer = SemanticVectorizer(self.config.rag_vectorizer_model)
                    elif self.config.rag_vectorizer=="tfidf":
                        from lollmsvectordb.lollms_vectorizers.tfidf_vectorizer import TFIDFVectorizer
                        vectorizer = TFIDFVectorizer()
                    elif self.config.rag_vectorizer=="openai":
                        from lollmsvectordb.lollms_vectorizers.openai_vectorizer import OpenAIVectorizer
                        vectorizer = OpenAIVectorizer(self.config.rag_vectorizer_model, self.config.rag_vectorizer_openai_key)
                    elif self.config.rag_vectorizer=="ollama":
                        from lollmsvectordb.lollms_vectorizers.ollama_vectorizer import OllamaVectorizer
                        vectorizer = OllamaVectorizer(self.config.rag_vectorizer_model, self.config.rag_service_url)

                    vdb = VectorDatabase(Path(parts[1])/f"{db_name}.sqlite", vectorizer, None if self.config.rag_vectorizer=="semantic" else self.model if self.model else TikTokenTokenizer(), n_neighbors=self.config.rag_n_chunks)       
                    self.active_rag_dbs.append({"name":parts[0],"path":parts[1],"vectorizer":vdb})
                except Exception as ex:
                    trace_exception(ex)
                    ASCIIColors.error(f"Couldn't load "+str(Path(parts[1])/f"{db_name}.sqlite")+" consider revectorizing it")

    def start_servers(self):

        ASCIIColors.yellow("* - * - * - Starting services - * - * - *")
        tts_services = []
        stt_services = []
        def start_ttt(*args, **kwargs):
            if self.config.enable_ollama_service:
                try:
                    from lollms.services.ttt.ollama.lollms_ollama import Service
                    self.ollama = Service(self, base_url=self.config.ollama_base_url)
                    tts_services.append("ollama")

                except Exception as ex:
                    trace_exception(ex)
                    self.warning(f"Couldn't load Ollama")

            if self.config.enable_vllm_service:
                try:
                    from lollms.services.ttt.vllm.lollms_vllm import Service
                    self.vllm = Service(self, base_url=self.config.vllm_url)
                    tts_services.append("vllm")
                except Exception as ex:
                    trace_exception(ex)
                    self.warning(f"Couldn't load vllm")
        ASCIIColors.execute_with_animation("Loading TTT services", start_ttt,ASCIIColors.color_blue)
        print("OK")
        def start_stt(*args, **kwargs):
            if self.config.whisper_activate or self.config.active_stt_service == "whisper":
                try:
                    from lollms.services.stt.whisper.lollms_whisper import LollmsWhisper
                    self.whisper = LollmsWhisper(self, self.config.whisper_model, self.lollms_paths.personal_outputs_path)
                    stt_services.append("whisper")
                except Exception as ex:
                    trace_exception(ex)
            if self.config.active_stt_service == "openai_whisper":
                from lollms.services.stt.openai_whisper.lollms_openai_whisper import LollmsOpenAIWhisper
                self.stt = LollmsOpenAIWhisper(self, self.config.openai_whisper_model, self.config.openai_whisper_key)
            elif self.config.active_stt_service == "whisper":
                from lollms.services.stt.whisper.lollms_whisper import LollmsWhisper
                self.stt = LollmsWhisper(self, self.config.whisper_model)

        ASCIIColors.execute_with_animation("Loading STT services", start_stt, ASCIIColors.color_blue)
        print("OK")

        def start_tts(*args, **kwargs):
            if self.config.active_tts_service == "xtts":
                ASCIIColors.yellow("Loading XTTS")
                try:
                    from lollms.services.tts.xtts.lollms_xtts import LollmsXTTS
                    voice=self.config.xtts_current_voice
                    if voice!="main_voice":
                        voices_folder = self.lollms_paths.custom_voices_path
                    else:
                        voices_folder = Path(__file__).parent.parent.parent/"services/xtts/voices"

                    self.xtts = LollmsXTTS(
                                            self,
                                            voices_folders=[voices_folder, self.lollms_paths.custom_voices_path], 
                                            freq=self.config.xtts_freq
                                        )
                except Exception as ex:
                    trace_exception(ex)
                    self.warning(f"Couldn't load XTTS")
            if self.config.active_tts_service == "eleven_labs_tts":
                from lollms.services.tts.eleven_labs_tts.lollms_eleven_labs_tts import LollmsElevenLabsTTS
                self.tts = LollmsElevenLabsTTS(self, self.config.elevenlabs_tts_model_id, self.config.elevenlabs_tts_voice_id,  self.config.elevenlabs_tts_key, stability=self.config.elevenlabs_tts_voice_stability, similarity_boost=self.config.elevenlabs_tts_voice_boost)
            elif self.config.active_tts_service == "openai_tts":
                from lollms.services.tts.open_ai_tts.lollms_openai_tts import LollmsOpenAITTS
                self.tts = LollmsOpenAITTS(self, self.config.openai_tts_model, self.config.openai_tts_voice,  self.config.openai_tts_key)
            elif self.config.active_tts_service == "fish_tts":
                from lollms.services.tts.fish.lollms_fish_tts import LollmsFishAudioTTS
                self.tts = LollmsFishAudioTTS(self, self.config.fish_tts_voice,  self.config.fish_tts_key)
            elif self.config.active_tts_service == "xtts" and self.xtts:
                self.tts = self.xtts

        ASCIIColors.execute_with_animation("Loading TTS services", start_tts, ASCIIColors.color_blue)
        print("OK")

        def start_tti(*args, **kwargs):
            if self.config.enable_sd_service:
                try:
                    from lollms.services.tti.sd.lollms_sd import LollmsSD
                    self.sd = LollmsSD(self, auto_sd_base_url=self.config.sd_base_url)
                except:
                    self.warning(f"Couldn't load SD")

            if self.config.enable_comfyui_service:
                try:
                    from lollms.services.tti.comfyui.lollms_comfyui import LollmsComfyUI
                    self.comfyui = LollmsComfyUI(self, comfyui_base_url=self.config.comfyui_base_url)
                except:
                    self.warning(f"Couldn't load SD")

            if self.config.active_tti_service == "diffusers":
                from lollms.services.tti.diffusers.lollms_diffusers import LollmsDiffusers
                self.tti = LollmsDiffusers(self)
            elif self.config.active_tti_service == "diffusers_client":
                from lollms.services.tti.diffusers_client.lollms_diffusers_client import LollmsDiffusersClient
                self.tti = LollmsDiffusersClient(self)
            elif self.config.active_tti_service == "autosd":
                if self.sd:
                    self.tti = self.sd
                else:
                    from lollms.services.tti.sd.lollms_sd import LollmsSD
                    self.tti = LollmsSD(self, auto_sd_base_url = self.config.sd_base_url)
            elif self.config.active_tti_service == "dall-e":
                from lollms.services.tti.dalle.lollms_dalle import LollmsDalle
                self.tti = LollmsDalle(self, self.config.dall_e_key)
            elif self.config.active_tti_service == "midjourney":
                from lollms.services.tti.midjourney.lollms_midjourney import LollmsMidjourney
                self.tti = LollmsMidjourney(self, self.config.midjourney_key, self.config.midjourney_timeout, self.config.midjourney_retries)
            elif self.config.active_tti_service == "comfyui" and (self.tti is None or self.tti.name!="comfyui"):
                if self.comfyui:
                    self.tti = self.comfyui
                else:
                    from lollms.services.tti.comfyui.lollms_comfyui import LollmsComfyUI
                    self.tti = LollmsComfyUI(self, comfyui_base_url=self.config.comfyui_base_url)

        ASCIIColors.execute_with_animation("Loading loacal TTI services", start_tti, ASCIIColors.color_blue)
        print("OK")
        def start_ttv(*args, **kwargs):
            if self.config.active_ttv_service == "lumalabs" and (self.ttv is None or self.tti.name!="lumalabs"):
                try:
                    from lollms.services.ttv.lumalabs.lollms_lumalabs import LollmsLumaLabs
                    self.sd = LollmsLumaLabs(self.config.lumalabs_key)
                except:
                    self.warning(f"Couldn't load SD")


        ASCIIColors.execute_with_animation("Loading loacal TTV services", start_ttv, ASCIIColors.color_blue)
        print("OK")



    def verify_servers(self, reload_all=False):
        ASCIIColors.yellow("* - * - * - Verifying services - * - * - *")

        try:
            ASCIIColors.blue("Loading active local TTT services")
            
            if self.config.enable_ollama_service and self.ollama is None:
                try:
                    from lollms.services.ttt.ollama.lollms_ollama import Service
                    self.ollama = Service(self, base_url=self.config.ollama_base_url)
                except Exception as ex:
                    trace_exception(ex)
                    self.warning(f"Couldn't load Ollama")

            if self.config.enable_vllm_service and self.vllm is None:
                try:
                    from lollms.services.ttt.vllm.lollms_vllm import Service
                    self.vllm = Service(self, base_url=self.config.vllm_url)
                except Exception as ex:
                    trace_exception(ex)
                    self.warning(f"Couldn't load vllm")

            ASCIIColors.blue("Loading local STT services")

            if self.config.whisper_activate and self.whisper is None:
                try:
                    from lollms.services.stt.whisper.lollms_whisper import LollmsWhisper
                    self.whisper = LollmsWhisper(self, self.config.whisper_model, self.lollms_paths.personal_outputs_path)
                except Exception as ex:
                    trace_exception(ex)
                    
            ASCIIColors.blue("Loading loacal TTS services")
            if self.config.active_tts_service == "xtts" and self.xtts is None:
                ASCIIColors.yellow("Loading XTTS")
                try:
                    from lollms.services.tts.xtts.lollms_xtts import LollmsXTTS
                    voice=self.config.xtts_current_voice
                    if voice!="main_voice":
                        voices_folder = self.lollms_paths.custom_voices_path
                    else:
                        voices_folder = Path(__file__).parent.parent.parent/"services/xtts/voices"

                    self.xtts = LollmsXTTS(
                                            self,
                                            voices_folders=[voices_folder, self.lollms_paths.custom_voices_path], 
                                            freq=self.config.xtts_freq
                                        )
                except Exception as ex:
                    trace_exception(ex)
                    self.warning(f"Couldn't load XTTS")

            ASCIIColors.blue("Loading local TTI services")
            if self.config.enable_sd_service and self.sd is None:
                try:
                    from lollms.services.tti.sd.lollms_sd import LollmsSD
                    self.sd = LollmsSD(self, auto_sd_base_url=self.config.sd_base_url)
                except:
                    self.warning(f"Couldn't load SD")

            if self.config.enable_comfyui_service and self.comfyui is None:
                try:
                    from lollms.services.tti.comfyui.lollms_comfyui import LollmsComfyUI
                    self.comfyui = LollmsComfyUI(self, comfyui_base_url=self.config.comfyui_base_url)
                except:
                    self.warning(f"Couldn't load Comfyui")

            ASCIIColors.blue("Activating TTI service")
            if self.config.active_tti_service == "diffusers" and (self.tti is None or self.tti.name!="diffusers" or self.tti.model!=self.config.diffusers_model):
                from lollms.services.tti.diffusers.lollms_diffusers import LollmsDiffusers
                self.tti = LollmsDiffusers(self)
            elif self.config.active_tti_service == "diffusers_client" and (self.tti.base_url!=self.config.diffusers_client_base_url or self.tti.name!="diffusers_client"):
                from lollms.services.tti.diffusers_client.lollms_diffusers_client import LollmsDiffusersClient
                self.tti = LollmsDiffusersClient(self, base_url=self.config.diffusers_client_base_url)
            elif self.config.active_tti_service == "autosd" and (self.tti is None or self.tti.name!="stable_diffusion"):
                if self.sd:
                    self.tti = self.sd
                else:
                    from lollms.services.tti.sd.lollms_sd import LollmsSD
                    self.tti = LollmsSD(self, auto_sd_base_url=self.config.sd_base_url)
            elif self.config.active_tti_service == "dall-e" and (self.tti is None or self.tti.name!="dall-e-2" or type(self.tti.name)!="dall-e-3"):
                from lollms.services.tti.dalle.lollms_dalle import LollmsDalle
                self.tti = LollmsDalle(self, self.config.dall_e_key)
            elif self.config.active_tti_service == "midjourney" and (self.tti is None or self.tti.name!="midjourney"):
                from lollms.services.tti.midjourney.lollms_midjourney import LollmsMidjourney
                self.tti = LollmsMidjourney(self, self.config.midjourney_key, self.config.midjourney_timeout, self.config.midjourney_retries)
            elif self.config.active_tti_service == "comfyui" and (self.tti is None or self.tti.name!="comfyui"):
                if self.comfyui:
                    self.tti = self.comfyui
                else:
                    from lollms.services.tti.comfyui.lollms_comfyui import LollmsComfyUI
                    self.tti = LollmsComfyUI(self, comfyui_base_url=self.config.comfyui_base_url)

            ASCIIColors.blue("Activating TTS service")
            if self.config.active_tts_service == "eleven_labs_tts":
                from lollms.services.tts.eleven_labs_tts.lollms_eleven_labs_tts import LollmsElevenLabsTTS
                self.tts = LollmsElevenLabsTTS(self, self.config.elevenlabs_tts_model_id, self.config.elevenlabs_tts_voice_id,  self.config.elevenlabs_tts_key, stability=self.config.elevenlabs_tts_voice_stability, similarity_boost=self.config.elevenlabs_tts_voice_boost)
            elif self.config.active_tts_service == "openai_tts" and (self.tts is None or self.tts.name!="openai_tts"):
                from lollms.services.tts.open_ai_tts.lollms_openai_tts import LollmsOpenAITTS
                self.tts = LollmsOpenAITTS(self, self.config.openai_tts_model, self.config.openai_tts_voice,  self.config.openai_tts_key)
            elif self.config.active_tts_service == "fish_tts":
                from lollms.services.tts.fish.lollms_fish_tts import LollmsFishAudioTTS
                self.tts = LollmsFishAudioTTS(self, self.config.fish_tts_voice,  self.config.fish_tts_key)
            elif self.config.active_tts_service == "xtts" and self.xtts:
                self.tts = self.xtts

            ASCIIColors.blue("Activating STT service")
            if self.config.active_stt_service == "openai_whisper" and (self.tts is None or self.tts.name!="openai_whisper"):
                from lollms.services.stt.openai_whisper.lollms_openai_whisper import LollmsOpenAIWhisper
                self.stt = LollmsOpenAIWhisper(self, self.config.openai_whisper_model, self.config.openai_whisper_key)
            elif self.config.active_stt_service == "whisper" and (self.tts is None or  self.tts.name!="whisper") :
                from lollms.services.stt.whisper.lollms_whisper import LollmsWhisper
                self.stt = LollmsWhisper(self, self.config.whisper_model)


            if self.config.active_ttv_service == "lumalabs" and (self.ttv is None or self.tti.name!="lumalabs"):
                try:
                    from lollms.services.ttv.lumalabs.lollms_lumalabs import LollmsLumaLabs
                    self.sd = LollmsLumaLabs(self.config.lumalabs_key)
                except:
                    self.warning(f"Couldn't load SD")

        except Exception as ex:
            trace_exception(ex)
            

    
    def process_data(
                        self, 
                        chunk:str, 
                        message_type,
                        parameters:dict=None, 
                        metadata:list=None, 
                        personality=None
                    ):
        
        pass

    def default_callback(self, chunk, type, generation_infos:dict):
        if generation_infos["nb_received_tokens"]==0:
            self.start_time = datetime.now()
        dt =(datetime.now() - self.start_time).seconds
        if dt==0:
            dt=1
        spd = generation_infos["nb_received_tokens"]/dt
        ASCIIColors.green(f"Received {generation_infos['nb_received_tokens']} tokens (speed: {spd:.2f}t/s)              ",end="\r",flush=True) 
        sys.stdout = sys.__stdout__
        sys.stdout.flush()
        if chunk:
            generation_infos["generated_text"] += chunk
        antiprompt = self.personality.detect_antiprompt(generation_infos["generated_text"])
        if antiprompt:
            ASCIIColors.warning(f"\n{antiprompt} detected. Stopping generation")
            generation_infos["generated_text"] = self.remove_text_from_string(generation_infos["generated_text"],antiprompt)
            return False
        else:
            generation_infos["nb_received_tokens"] += 1
            generation_infos["first_chunk"]=False
            # if stop generation is detected then stop
            if not self.cancel_gen:
                return True
            else:
                self.cancel_gen = False
                ASCIIColors.warning("Generation canceled")
                return False
   
    def remove_text_from_string(self, string, text_to_find):
        """
        Removes everything from the first occurrence of the specified text in the string (case-insensitive).

        Parameters:
        string (str): The original string.
        text_to_find (str): The text to find in the string.

        Returns:
        str: The updated string.
        """
        index = string.lower().find(text_to_find.lower())

        if index != -1:
            string = string[:index]

        return string

    def load_binding(self):
        try:
            binding = BindingBuilder().build_binding(self.config, self.lollms_paths, lollmsCom=self)
            return binding    
        except Exception as ex:
            self.error("Couldn't load binding")
            self.info("Trying to reinstall binding")
            trace_exception(ex)
            try:
                binding = BindingBuilder().build_binding(self.config, self.lollms_paths,installation_option=InstallOption.FORCE_INSTALL, lollmsCom=self)
            except Exception as ex:
                self.error("Couldn't reinstall binding")
                trace_exception(ex)
            return None    

    
    def load_model(self):
        try:
            model = ModelBuilder(self.binding).get_model()
            for personality in self.mounted_personalities:
                if personality is not None:
                    personality.model = model
        except Exception as ex:
            self.error("Couldn't load model.")
            ASCIIColors.error(f"Couldn't load model. Please verify your configuration file at {self.lollms_paths.personal_configuration_path} or use the next menu to select a valid model")
            ASCIIColors.error(f"Binding returned this exception : {ex}")
            trace_exception(ex)
            ASCIIColors.error(f"{self.config.get_model_path_infos()}")
            print("Please select a valid model or install a new one from a url")
            model = None

        return model



    def mount_personality(self, id:int, callback=None):
        try:
            personality = PersonalityBuilder(self.lollms_paths, self.config, self.model, self, callback=callback).build_personality(id)
            if personality.model is not None:
                try:
                    self.cond_tk = personality.model.tokenize(personality.personality_conditioning)
                    self.n_cond_tk = len(self.cond_tk)
                    ASCIIColors.success(f"Personality  {personality.name} mounted successfully")
                except:
                    self.cond_tk = []      
                    self.n_cond_tk = 0      
            else:
                ASCIIColors.success(f"Personality  {personality.name} mounted successfully but no model is selected")
        except Exception as ex:
            ASCIIColors.error(f"Couldn't load personality. Please verify your configuration file at {self.lollms_paths.personal_configuration_path} or use the next menu to select a valid personality")
            ASCIIColors.error(f"Binding returned this exception : {ex}")
            trace_exception(ex)
            ASCIIColors.error(f"{self.config.get_personality_path_infos()}")
            if id == self.config.active_personality_id:
                self.config.active_personality_id=len(self.config.personalities)-1
            personality = None
        
        self.mounted_personalities.append(personality)
        return personality
    
    def mount_personalities(self, callback = None):
        self.mounted_personalities = []
        to_remove = []
        for i in range(len(self.config["personalities"])):
            p = self.mount_personality(i, callback = None)
            if p is None:
                to_remove.append(i)
        to_remove.sort(reverse=True)
        for i in to_remove:
            self.unmount_personality(i)

        if self.config.active_personality_id>=0 and self.config.active_personality_id<len(self.mounted_personalities):
            self.personality = self.mounted_personalities[self.config.active_personality_id]
        else:
            self.config["personalities"].insert(0, "generic/lollms")
            self.mount_personality(0, callback = None)
            self.config.active_personality_id = 0
            self.personality = self.mounted_personalities[self.config.active_personality_id]

    def mount_extensions(self, callback = None):
        self.mounted_extensions = []
        to_remove = []
        for i in range(len(self.config["extensions"])):
            p = self.mount_extension(i, callback = None)
            if p is None:
                to_remove.append(i)
        to_remove.sort(reverse=True)
        for i in to_remove:
            self.unmount_extension(i)


    def set_personalities_callbacks(self, callback: Callable[[str, int, dict], bool]=None):
        for personality in self.mount_personalities:
            personality.setCallback(callback)

    def unmount_extension(self, id:int)->bool:
        if id<len(self.config.extensions):
            del self.config.extensions[id]
            if id>=0 and id<len(self.mounted_extensions):
                del self.mounted_extensions[id]
            self.config.save_config()
            return True
        else:
            return False

            
    def unmount_personality(self, id:int)->bool:
        if id<len(self.config.personalities):
            del self.config.personalities[id]
            del self.mounted_personalities[id]
            if self.config.active_personality_id>=id:
                self.config.active_personality_id-=1

            self.config.save_config()
            return True
        else:
            return False


    def select_personality(self, id:int):
        if id<len(self.config.personalities):
            self.config.active_personality_id = id
            self.personality = self.mounted_personalities[id]
            self.config.save_config()
            return True
        else:
            return False


    def load_personality(self, callback=None):
        try:
            personality = PersonalityBuilder(self.lollms_paths, self.config, self.model, self, callback=callback).build_personality()
        except Exception as ex:
            ASCIIColors.error(f"Couldn't load personality. Please verify your configuration file at {self.configuration_path} or use the next menu to select a valid personality")
            ASCIIColors.error(f"Binding returned this exception : {ex}")
            ASCIIColors.error(f"{self.config.get_personality_path_infos()}")
            print("Please select a valid model or install a new one from a url")
            personality = None
        return personality

    @staticmethod   
    def reset_paths(lollms_paths:LollmsPaths):
        lollms_paths.resetPaths()

    @staticmethod   
    def reset_all_installs(lollms_paths:LollmsPaths):
        ASCIIColors.info("Removeing all configuration files to force reinstall")
        ASCIIColors.info(f"Searching files from {lollms_paths.personal_configuration_path}")
        for file_path in lollms_paths.personal_configuration_path.iterdir():
            if file_path.name!=f"{lollms_paths.tool_prefix}local_config.yaml" and file_path.suffix.lower()==".yaml":
                file_path.unlink()
                ASCIIColors.info(f"Deleted file: {file_path}")


    #languages:
    def get_personality_languages(self):
        languages = [self.personality.default_language]
        persona_language_path = self.lollms_paths.personalities_zoo_path/self.personality.category/self.personality.name.replace(" ","_")/"languages"
        for language_file in persona_language_path.glob("*.yaml"):
            language_code = language_file.stem
            languages.append(language_code)
        # Construire le chemin vers le dossier contenant les fichiers de langue pour la personnalité actuelle
        languages_dir = self.lollms_paths.personal_configuration_path / "personalities" / self.personality.name
        if self.personality.language:
            default_language = self.personality.language.lower().strip().split()[0]
        else:
            default_language = "english"
        # Vérifier si le dossier existe
        languages_dir.mkdir(parents=True, exist_ok=True)
        
        # Itérer sur chaque fichier YAML dans le dossier
        for language_file in languages_dir.glob("languages_*.yaml"):
            # Improved extraction of the language code to handle names with underscores
            parts = language_file.stem.split("_")
            if len(parts) > 2:
                language_code = "_".join(parts[1:])  # Rejoin all parts after "languages"
            else:
                language_code = parts[-1]
            
            if language_code != default_language and language_code not in languages:
                languages.append(language_code)
        
        return languages



    def set_personality_language(self, language:str):
        if language is None or  language == "":
            return False
        language = language.lower().strip().split()[0]
        self.personality.set_language(language)

        self.config.current_language=language
        self.config.save_config()
        return True

    def del_personality_language(self, language:str):
        if language is None or  language == "":
            return False
        
        language = language.lower().strip().split()[0]
        default_language = self.personality.language.lower().strip().split()[0]
        if language == default_language:
            return False # Can't remove the default language
                
        language_path = self.lollms_paths.personal_configuration_path/"personalities"/self.personality.name/f"languages_{language}.yaml"
        if language_path.exists():
            try:
                language_path.unlink()
            except Exception as ex:
                return False
            if self.config.current_language==language:
                self.config.current_language="english"
                self.config.save_config()
        return True

    def recover_discussion(self,client_id, message_index=-1):
        messages = self.session.get_client(client_id).discussion.get_messages()
        discussion=""
        for msg in messages[:-1]:
            if message_index!=-1 and msg>message_index:
                break
            discussion += "\n" + self.config.discussion_prompt_separator + msg.sender + ": " + msg.content.strip()
        return discussion
    # -------------------------------------- Prompt preparing
    def prepare_query(self, client_id: str, message_id: int = -1, is_continue: bool = False, n_tokens: int = 0, generation_type = None, force_using_internet=False, previous_chunk="") -> Tuple[str, str, List[str]]:
        """
        Prepares the query for the model.

        Args:
            client_id (str): The client ID.
            message_id (int): The message ID. Default is -1.
            is_continue (bool): Whether the query is a continuation. Default is False.
            n_tokens (int): The number of tokens. Default is 0.

        Returns:
            Tuple[str, str, List[str]]: The prepared query, original message content, and tokenized query.
        """
        skills_detials=[]
        skills = []
        documentation_entries = []
        start_ai_header_id_template     = self.config.start_ai_header_id_template
        end_ai_header_id_template       = self.config.end_ai_header_id_template

        system_message_template     = self.config.system_message_template

        if self.personality.callback is None:
            self.personality.callback = partial(self.process_data, client_id=client_id)
        # Get the list of messages
        client = self.session.get_client(client_id)
        discussion = client.discussion
        messages = discussion.get_messages()

        # Find the index of the message with the specified message_id
        message_index = -1
        for i, message in enumerate(messages):
            if message.id == message_id:
                message_index = i
                break
        
        # Define current message
        current_message = messages[message_index]

        # Build the conditionning text block
        default_language = self.personality.language.lower().strip().split()[0]
        current_language = self.config.current_language.lower().strip().split()[0]

        if current_language and  current_language!= self.personality.language:
            language_path = self.lollms_paths.personal_configuration_path/"personalities"/self.personality.name/f"languages_{current_language}.yaml"
            if not language_path.exists():
                self.info(f"This is the first time this personality speaks {current_language}\nLollms is reconditionning the persona in that language.\nThis will be done just once. Next time, the personality will speak {current_language} out of the box")
                language_path.parent.mkdir(exist_ok=True, parents=True)
                # Translating
                conditionning = self.tasks_library.translate_conditionning(self.personality._personality_conditioning, self.personality.language, current_language)
                welcome_message = self.tasks_library.translate_message(self.personality.welcome_message, self.personality.language, current_language)
                with open(language_path,"w",encoding="utf-8", errors="ignore") as f:
                    yaml.safe_dump({"personality_conditioning":conditionning,"welcome_message":welcome_message}, f)
            else:
                with open(language_path,"r",encoding="utf-8", errors="ignore") as f:
                    language_pack = yaml.safe_load(f)
                    conditionning = language_pack.get("personality_conditioning", language_pack.get("conditionning", self.personality.personality_conditioning))
        else:
            conditionning = self.personality._personality_conditioning

        if len(conditionning)>0:
            conditionning =  self.start_header_id_template + system_message_template + self.end_header_id_template + self.personality.replace_keys(conditionning, self.personality.conditionning_commands) + ("" if conditionning[-1]==self.separator_template else self.separator_template)

        # Check if there are document files to add to the prompt
        internet_search_results = ""
        internet_search_infos = []
        documentation = ""
        knowledge = ""
        knowledge_infos = {"titles":[],"contents":[]}


        # boosting information
        if self.config.positive_boost:
            positive_boost=f"{self.system_custom_header('important information')}"+self.config.positive_boost+"\n"
            n_positive_boost = len(self.model.tokenize(positive_boost))
        else:
            positive_boost=""
            n_positive_boost = 0

        if self.config.negative_boost:
            negative_boost=f"{self.system_custom_header('important information')}"+self.config.negative_boost+"\n"
            n_negative_boost = len(self.model.tokenize(negative_boost))
        else:
            negative_boost=""
            n_negative_boost = 0

        if self.config.fun_mode:
            fun_mode=f"{self.system_custom_header('important information')} Fun mode activated. In this mode you must answer in a funny playful way. Do not be serious in your answers. Each answer needs to make the user laugh.\n"
            n_fun_mode = len(self.model.tokenize(positive_boost))
        else:
            fun_mode=""
            n_fun_mode = 0

        discussion = None
        if generation_type != "simple_question":

            if self.config.activate_internet_search or force_using_internet or generation_type == "full_context_with_internet":
                if discussion is None:
                    discussion = self.recover_discussion(client_id)
                if self.config.internet_activate_search_decision:
                    self.personality.step_start(f"Requesting if {self.personality.name} needs to search internet to answer the user")
                    q = f"{self.separator_template}".join([
                        f"{self.system_custom_header('discussion')}",
                        f"{discussion[-2048:]}",  # Use the last 2048 characters of the discussion for context
                        self.system_full_header,
                        f"You are a sophisticated web search query builder. Your task is to help the user by crafting a precise and concise web search query based on their request.",
                        f"Carefully read the discussion and generate a web search query that will retrieve the most relevant information to answer the last message from {self.config.user_name}.",
                        f"Do not answer the prompt directly. Do not provide explanations or additional information.",
                        f"{self.system_custom_header('current date')}{datetime.now()}",
                        f"{self.ai_custom_header('websearch query')}"
                    ])
                    need = not self.personality.yes_no(q, discussion)
                    self.personality.step_end(f"Requesting if {self.personality.name} needs to search internet to answer the user")
                    self.personality.step("Yes" if need else "No")
                else:
                    need=True
                if need:
                    self.personality.step_start("Crafting internet search query")
                    q = f"{self.separator_template}".join([
                        f"{self.system_custom_header('discussion')}",
                        f"{discussion[-2048:]}",  # Use the last 2048 characters of the discussion for context
                        self.system_full_header,
                        f"You are a sophisticated web search query builder. Your task is to help the user by crafting a precise and concise web search query based on their request.",
                        f"Carefully read the discussion and generate a web search query that will retrieve the most relevant information to answer the last message from {self.config.user_name}.",
                        f"Do not answer the prompt directly. Do not provide explanations or additional information.",
                        f"{self.system_custom_header('current date')}{datetime.now()}",
                        f"{self.ai_custom_header('websearch query')}"
                    ])
                    query = self.personality.fast_gen(q, max_generation_size=256, show_progress=True, callback=self.personality.sink)
                    query = query.replace("\"","")
                    self.personality.step_end("Crafting internet search query")
                    self.personality.step(f"web search query: {query}")

                    if self.config.internet_quick_search:
                        self.personality.step_start("Performing Internet search (quick mode)")
                    else:
                        self.personality.step_start("Performing Internet search (advanced mode: slower but more accurate)")

                    internet_search_results=f"{self.system_full_header}Use the web search results data to answer {self.config.user_name}. Try to extract information from the web search and use it to perform the requested task or answer the question. Do not come up with information that is not in the websearch results. Try to stick to the websearch results and clarify if your answer was based on the resuts or on your own culture. If you don't know how to perform the task, then tell the user politely that you need more data inputs.{self.separator_template}{self.start_header_id_template}Web search results{self.end_header_id_template}\n"

                    chunks:List[Chunk] = self.personality.internet_search_with_vectorization(query, self.config.internet_quick_search, asses_using_llm=self.config.activate_internet_pages_judgement)
                    
                    if len(chunks)>0:
                        for chunk in chunks:
                            internet_search_infos.append({
                                "title":chunk.doc.title,
                                "url":chunk.doc.path,
                                "brief":chunk.text
                            })
                            internet_search_results += self.system_custom_header("search result chunk")+f"\nchunk_infos:{chunk.doc.path}\nchunk_title:{chunk.doc.title}\ncontent:{chunk.text}\n"
                    else:
                        internet_search_results += "The search response was empty!\nFailed to recover useful information from the search engine.\n"
                    internet_search_results += self.system_custom_header("information") + "Use the search results to answer the user question."
                    if self.config.internet_quick_search:
                        self.personality.step_end("Performing Internet search (quick mode)")
                    else:
                        self.personality.step_end("Performing Internet search (advanced mode: slower but more advanced)")

            if self.personality.persona_data_vectorizer:
                if documentation=="":
                    documentation=f"{self.separator_template}{self.start_header_id_template}Documentation:\n"


                if not self.config.rag_deactivate:
                    if self.config.rag_build_keys_words:
                        if discussion is None:
                            discussion = self.recover_discussion(client_id)
                        query = self.personality.fast_gen(f"{self.separator_template}{self.start_header_id_template}instruction: Read the discussion and rewrite the last prompt for someone who didn't read the entire discussion.\nDo not answer the prompt. Do not add explanations.{self.separator_template}{self.start_header_id_template}discussion:\n{discussion[-2048:]}{self.separator_template}{self.start_header_id_template}enhanced query: ", max_generation_size=256, show_progress=True)
                        ASCIIColors.cyan(f"Query:{query}")
                    else:
                        query = current_message.content
                    try:
                        chunks:List[Chunk] = self.personality.persona_data_vectorizer.search(query, int(self.config.rag_n_chunks))
                        for chunk in chunks:
                            if self.config.rag_put_chunk_informations_into_context:
                                documentation += f"{self.start_header_id_template}document chunk{self.end_header_id_template}\ndocument title: {chunk.doc.title}\nchunk content:\n{chunk.text}\n"
                            else:
                                documentation += f"{self.start_header_id_template}chunk{self.end_header_id_template}\n{chunk.text}\n"

                        documentation += f"{self.separator_template}{self.start_header_id_template}important information: Use the documentation data to answer the user questions. If the data is not present in the documentation, please tell the user that the information he is asking for does not exist in the documentation section. It is strictly forbidden to give the user an answer without having actual proof from the documentation.\n"

                    except Exception as ex:
                        trace_exception(ex)
                        self.warning("Couldn't add documentation to the context. Please verify the vector database")
                else:
                    docs = self.personality.persona_data_vectorizer.list_documents()
                    for doc in docs:
                        documentation += self.personality.persona_data_vectorizer.get_document(doc['title'])
            
            if not self.personality.ignore_discussion_documents_rag:
                query = None
                if len(self.active_rag_dbs) > 0 :
                    if discussion is None:
                        discussion = self.recover_discussion(client_id)

                    if self.config.rag_build_keys_words:
                        self.personality.step_start("Building vector store query")
                        q = f"{self.separator_template}".join([
                            "make a RAG vector database query from the last user prompt given this discussion.",
                            f"{self.system_custom_header('discussion')}",
                            "---",
                            f"{discussion[-2048:]}",
                            "---",
                        ])
                        template = """{
"query": "[the rag query deduced from the last user prompt]"
}
"""
                        query = self.personality.generate_code(q, self.personality.image_files, template, callback=self.personality.sink)
                        query = json.loads(query)
                        query = query["query"]
                        self.personality.step_end("Building vector store query")
                        ASCIIColors.magenta(f"Query: {query}")
                        self.personality.step(f"Query: {query}")
                    else:
                        query = current_message.content
                    if documentation=="":
                        documentation=f"{self.separator_template}".join([
                            f"{self.system_custom_header('important information')}",
                            "Always refer to the provided documentation to answer user questions accurately.",
                            "Absence of Information: If the required information is not available in the documentation, inform the user that the requested information is not present in the documentation section.",
                            "Strict Adherence to Documentation: It is strictly prohibited to provide answers without concrete evidence from the documentation.",
                            "Cite Your Sources: After providing an answer, include the full path to the document where the information was found.",
                            self.system_custom_header("Documentation")])
                        documentation += f"{self.separator_template}"
                    full_documentation=""
                    if self.config.contextual_summary:
                        for db in self.active_rag_dbs:
                            v:VectorDatabase = db["vectorizer"]
                            docs = v.list_documents()
                            for doc in docs:
                                document=v.get_document(document_path = doc["path"])
                                self.personality.step_start(f"Summaryzing document {doc['path']}")
                                def post_process(summary):
                                    return summary
                                summary = self.personality.summarize_text(document, 
                                                                        f"Extract information from the following text chunk to answer this request.\n{self.system_custom_header('query')}{query}", chunk_summary_post_processing=post_process, callback=self.personality.sink)
                                self.personality.step_end(f"Summaryzing document {doc['path']}")
                                document_infos = f"{self.separator_template}".join([
                                    self.system_custom_header('document contextual summary'),
                                    f"source_document_title:{doc['title']}",
                                    f"source_document_path:{doc['path']}",
                                    f"content:\n{summary}\n"
                                ])
                                documentation_entries.append({
                                    "document_title":doc['title'],
                                    "document_path":doc['path'],
                                    "chunk_content":summary,
                                    "chunk_size":0,
                                    "similarity":0,
                                })
                                if summary!="":
                                    v.add_summaries(doc['path'],[{"context":query, "summary":summary}])
                                full_documentation += document_infos
                        documentation += self.personality.summarize_text(full_documentation, f"Extract information from the current text chunk and previous text chunks to answer the query. If there is no information about the query, just return an empty string.\n{self.system_custom_header('query')}{query}", callback=self.personality.sink)
                    else:
                        results = []
                        recovered_ids=[[] for _ in range(len(self.active_rag_dbs))]
                        hop_id = 0
                        while( len(results)<self.config.rag_n_chunks and hop_id<self.config.rag_max_n_hops):
                            i=0
                            hop_id +=1
                            for db in self.active_rag_dbs:
                                v = db["vectorizer"]
                                r=v.search(query, self.config.rag_n_chunks, recovered_ids[i])
                                recovered_ids[i]+=[rg.chunk_id for rg in r]
                                if self.config.rag_activate_multi_hops:
                                    r = [rg for rg in r if self.personality.verify_rag_entry(query, rg.text)]
                                results+=r
                                i+=1
                            if len(results)>=self.config.rag_n_chunks:
                                break
                        n_neighbors = self.active_rag_dbs[0]["vectorizer"].n_neighbors
                        sorted_results = sorted(results, key=lambda x: x.distance)[:n_neighbors]

                        for chunk in sorted_results:
                            document_infos = f"{self.separator_template}".join([
                                f"{self.start_header_id_template}document chunk{self.end_header_id_template}",
                                f"source_document_title:{chunk.doc.title}",
                                f"source_document_path:{chunk.doc.path}",
                                f"content:\n{chunk.text}\n"
                            ])
                            documentation_entries.append({
                                "document_title":chunk.doc.title,
                                "document_path":chunk.doc.path,
                                "chunk_content":chunk.text,
                                "chunk_size":chunk.nb_tokens,
                                "similarity":1-chunk.distance,
                            })
                            documentation += document_infos
                            
                if (len(client.discussion.text_files) > 0) and client.discussion.vectorizer is not None:
                    if not self.config.rag_deactivate:
                        if discussion is None:
                            discussion = self.recover_discussion(client_id)

                        if documentation=="":
                            documentation=f"{self.separator_template}".join([
                                f"{self.separator_template}{self.start_header_id_template}important information{self.end_header_id_template}Utilize Documentation Data: Always refer to the provided documentation to answer user questions accurately.",
                                "Absence of Information: If the required information is not available in the documentation, inform the user that the requested information is not present in the documentation section.",
                                "Strict Adherence to Documentation: It is strictly prohibited to provide answers without concrete evidence from the documentation.",
                                "Cite Your Sources: After providing an answer, include the full path to the document where the information was found.",
                                f"{self.start_header_id_template}Documentation{self.end_header_id_template}"])
                            documentation += f"{self.separator_template}"

                        if query is None:
                            if self.config.rag_build_keys_words:
                                self.personality.step_start("Building vector store query")
                                query = self.personality.fast_gen(f"{self.separator_template}{self.start_header_id_template}instruction: Read the discussion and rewrite the last prompt for someone who didn't read the entire discussion.\nDo not answer the prompt. Do not add explanations.{self.separator_template}{self.start_header_id_template}discussion:\n{discussion[-2048:]}{self.separator_template}{self.start_header_id_template}enhanced query: ", max_generation_size=256, show_progress=True, callback=self.personality.sink)
                                self.personality.step_end("Building vector store query")
                                ASCIIColors.cyan(f"Query: {query}")
                            else:
                                query = current_message.content


                        full_documentation=""
                        if self.config.contextual_summary:
                            v = client.discussion.vectorizer
                            docs = v.list_documents()
                            for doc in docs:
                                document=v.get_document(document_path = doc["path"])
                                self.personality.step_start(f"Summeryzing document {doc['path']}")
                                summary = self.personality.summarize_text(document, f"Extract information from the following text chunk to answer this request. If there is no information about the query, just return an empty string.\n{self.system_custom_header('query')}{query}", callback=self.personality.sink)
                                self.personality.step_end(f"Summeryzing document {doc['path']}")
                                document_infos = f"{self.separator_template}".join([
                                    self.system_custom_header('document contextual summary'),
                                    f"source_document_title:{doc['title']}",
                                    f"source_document_path:{doc['path']}",
                                    f"content:\n{summary}\n"
                                ])
                                documentation_entries.append({
                                    "document_title":doc['title'],
                                    "document_path":doc['path'],
                                    "chunk_content":summary,
                                    "chunk_size":0,
                                    "similarity":0,
                                })
                                if summary!="":
                                    v.add_summaries(doc['path'],[{"context":query, "summary":summary}])
                                full_documentation += document_infos
                            documentation += self.personality.summarize_text(full_documentation, f"Extract information from the current text chunk and previous text chunks to answer the query. If there is no information about the query, just return an empty string.\n{self.system_custom_header('query')}{query}", callback=self.personality.sink)
                        else:
                            try:
                                chunks:List[Chunk] = client.discussion.vectorizer.search(query, int(self.config.rag_n_chunks))
                                for chunk in chunks:
                                    if self.config.rag_put_chunk_informations_into_context:
                                        documentation += f"{self.start_header_id_template}document chunk{self.end_header_id_template}\ndocument title: {chunk.doc.title}\nchunk content:\n{chunk.text}\n"
                                    else:
                                        documentation += f"{self.start_header_id_template}chunk{self.end_header_id_template}\n{chunk.text}\n"

                                documentation += f"{self.separator_template}{self.start_header_id_template}important information: Use the documentation data to answer the user questions. If the data is not present in the documentation, please tell the user that the information he is asking for does not exist in the documentation section. It is strictly forbidden to give the user an answer without having actual proof from the documentation.\n"
                            except Exception as ex:
                                trace_exception(ex)
                                self.warning("Couldn't add documentation to the context. Please verify the vector database")
                    else:
                        docs = client.discussion.vectorizer.get_all_documents()
                        documentation += "\n\n".join(docs) + "\n"
                            
                # Check if there is discussion knowledge to add to the prompt
                if self.config.activate_skills_lib:
                    try:
                        self.personality.step_start("Querying skills library")
                        if discussion is None:
                            discussion = self.recover_discussion(client_id)
                        self.personality.step_start("Building query")
                        query = self.personality.generate_code(f"""Your task is to carefully read the provided discussion and reformulate {self.config.user_name}'s request concisely.
{self.system_custom_header("discussion")}
{discussion[-2048:]}
""", template="""{
    "request": "the reformulated request"
}""", callback=self.personality.sink)
                        query_code = json.loads(query)
                        query = query_code["request"]
                        self.personality.step_end("Building query")
                        self.personality.step(f"query: {query}")
                        # skills = self.skills_library.query_entry(query)
                        self.personality.step_start("Adding skills")
                        if self.config.debug:
                            ASCIIColors.info(f"Query : {query}")
                        skill_titles, skills, similarities = self.skills_library.query_vector_db(query, top_k=3, min_similarity=self.config.rag_min_correspondance)#query_entry_fts(query)
                        skills_detials=[{"title": title, "content":content, "similarity":similarity} for title, content, similarity in zip(skill_titles, skills, similarities)]

                        if len(skills)>0:
                            if knowledge=="":
                                knowledge=f"{self.system_custom_header(knowledge)}\n"
                            for i,skill in enumerate(skills_detials):
                                knowledge += self.system_custom_header(f"knowledge {i}") +f"\ntitle:\n{skill['title']}\ncontent:\n{skill['content']}\n"
                        self.personality.step_end("Adding skills")
                        self.personality.step_end("Querying skills library")
                    except Exception as ex:
                        trace_exception(ex)
                        self.warning("Couldn't add long term memory information to the context. Please verify the vector database")        # Add information about the user
                        self.personality.step_end("Adding skills")
                        self.personality.step_end("Querying skills library",False)
        user_description=""
        if self.config.use_user_informations_in_discussion:
            user_description=f"{self.start_header_id_template}User description{self.end_header_id_template}\n"+self.config.user_description+"\n"


        # Tokenize the conditionning text and calculate its number of tokens
        tokens_conditionning = self.model.tokenize(conditionning)
        n_cond_tk = len(tokens_conditionning)


        # Tokenize the internet search results text and calculate its number of tokens
        if len(internet_search_results)>0:
            tokens_internet_search_results = self.model.tokenize(internet_search_results)
            n_isearch_tk = len(tokens_internet_search_results)
        else:
            tokens_internet_search_results = []
            n_isearch_tk = 0


        # Tokenize the documentation text and calculate its number of tokens
        if len(documentation)>0:
            tokens_documentation = self.model.tokenize(documentation)
            n_doc_tk = len(tokens_documentation)
            self.info(f"The documentation consumes {n_doc_tk} tokens")
            if n_doc_tk>3*self.config.ctx_size/4:
                ASCIIColors.warning("The documentation is bigger than 3/4 of the context ")
                self.warning("The documentation is bigger than 3/4 of the context ")
            if n_doc_tk>=self.config.ctx_size-512:
                ASCIIColors.warning("The documentation is too big for the context")
                self.warning("The documentation is too big for the context it'll be cropped")
                documentation = self.model.detokenize(tokens_documentation[:(self.config.ctx_size-512)])
                n_doc_tk = self.config.ctx_size-512

        else:
            tokens_documentation = []
            n_doc_tk = 0

        # Tokenize the knowledge text and calculate its number of tokens
        if len(knowledge)>0:
            tokens_history = self.model.tokenize(knowledge)
            n_history_tk = len(tokens_history)
        else:
            tokens_history = []
            n_history_tk = 0


        # Tokenize user description
        if len(user_description)>0:
            tokens_user_description = self.model.tokenize(user_description)
            n_user_description_tk = len(tokens_user_description)
        else:
            tokens_user_description = []
            n_user_description_tk = 0


        # Calculate the total number of tokens between conditionning, documentation, and knowledge
        total_tokens = n_cond_tk + n_isearch_tk + n_doc_tk + n_history_tk + n_user_description_tk + n_positive_boost + n_negative_boost + n_fun_mode

        # Calculate the available space for the messages
        available_space = self.config.ctx_size - n_tokens - total_tokens

        # if self.config.debug:
        #     self.info(f"Tokens summary:\nConditionning:{n_cond_tk}\nn_isearch_tk:{n_isearch_tk}\ndoc:{n_doc_tk}\nhistory:{n_history_tk}\nuser description:{n_user_description_tk}\nAvailable space:{available_space}",10)

        # Raise an error if the available space is 0 or less
        if available_space<1:
            ASCIIColors.red(f"available_space:{available_space}")
            ASCIIColors.red(f"n_doc_tk:{n_doc_tk}")
            
            ASCIIColors.red(f"n_history_tk:{n_history_tk}")
            ASCIIColors.red(f"n_isearch_tk:{n_isearch_tk}")
            
            ASCIIColors.red(f"n_tokens:{n_tokens}")
            ASCIIColors.red(f"self.config.max_n_predict:{self.config.max_n_predict}")
            self.InfoMessage(f"Not enough space in context!!\nVerify that your vectorization settings for documents or internet search are realistic compared to your context size.\nYou are {available_space} short of context!")
            raise Exception("Not enough space in context!!")

        # Accumulate messages until the cumulative number of tokens exceeds available_space
        tokens_accumulated = 0


        # Initialize a list to store the full messages
        full_message_list = []
        # If this is not a continue request, we add the AI prompt
        if not is_continue:
            message_tokenized = self.model.tokenize(
                self.personality.ai_message_prefix.strip()
            )
            full_message_list.append(message_tokenized)
            # Update the cumulative number of tokens
            tokens_accumulated += len(message_tokenized)


        if generation_type != "simple_question":
            # Accumulate messages starting from message_index
            for i in range(message_index, -1, -1):
                message = messages[i]

                # Check if the message content is not empty and visible to the AI
                if message.content != '' and (
                        message.message_type <= MSG_OPERATION_TYPE.MSG_OPERATION_TYPE_SET_CONTENT_INVISIBLE_TO_USER.value and message.message_type != MSG_OPERATION_TYPE.MSG_OPERATION_TYPE_SET_CONTENT_INVISIBLE_TO_AI.value):

                    # Tokenize the message content
                    if self.config.use_model_name_in_discussions:
                        if message.model:
                            msg =  f"{self.separator_template}" + f"{start_ai_header_id_template if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.start_user_header_id_template}{message.sender}({message.model}){end_ai_header_id_template  if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.end_user_header_id_template}" + message.content.strip()
                        else:
                            msg = f"{self.separator_template}" + f"{start_ai_header_id_template if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.start_user_header_id_template}{message.sender}{end_ai_header_id_template  if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.end_user_header_id_template}" + message.content.strip()
                        message_tokenized = self.model.tokenize(msg)
                    else:
                        msg_value= f"{self.separator_template}" + f"{start_ai_header_id_template if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.start_user_header_id_template}{message.sender}{end_ai_header_id_template  if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.end_user_header_id_template}" + message.content.strip()
                        message_tokenized = self.model.tokenize(
                            msg_value
                        )
                    # Check if adding the message will exceed the available space
                    if tokens_accumulated + len(message_tokenized) > available_space:
                        # Update the cumulative number of tokens
                        msg = message_tokenized[-(available_space-tokens_accumulated):]
                        tokens_accumulated += available_space-tokens_accumulated
                        full_message_list.insert(0, msg)
                        break

                    # Add the tokenized message to the full_message_list
                    full_message_list.insert(0, message_tokenized)

                    # Update the cumulative number of tokens
                    tokens_accumulated += len(message_tokenized)
        else:
            message = messages[message_index]

            # Check if the message content is not empty and visible to the AI
            if message.content != '' and (
                    message.message_type <= MSG_OPERATION_TYPE.MSG_OPERATION_TYPE_SET_CONTENT_INVISIBLE_TO_USER.value and message.message_type != MSG_OPERATION_TYPE.MSG_OPERATION_TYPE_SET_CONTENT_INVISIBLE_TO_AI.value):

                if self.config.use_model_name_in_discussions:
                    if message.model:
                        msg = f"{self.separator_template}{start_ai_header_id_template if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.start_user_header_id_template}{message.sender}({message.model}){end_ai_header_id_template  if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.end_user_header_id_template}" + message.content.strip()
                    else:
                        msg = f"{self.separator_template}{start_ai_header_id_template if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.start_user_header_id_template}{message.sender}{end_ai_header_id_template  if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.end_user_header_id_template}" + message.content.strip()
                    message_tokenized = self.model.tokenize(msg)
                else:
                    message_tokenized = self.model.tokenize(
                        f"{self.separator_template}{start_ai_header_id_template if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.start_user_header_id_template}{message.sender}{end_ai_header_id_template  if message.sender_type == SENDER_TYPES.SENDER_TYPES_AI else self.end_user_header_id_template}" + message.content.strip()
                    )

                # Add the tokenized message to the full_message_list
                full_message_list.insert(0, message_tokenized)

                # Update the cumulative number of tokens
                tokens_accumulated += len(message_tokenized)

        # Build the final discussion messages by detokenizing the full_message_list
        discussion_messages = ""
        for i in range(len(full_message_list)-1 if not is_continue else len(full_message_list)):
            message_tokens = full_message_list[i]
            discussion_messages += self.model.detokenize(message_tokens)
        
        if len(full_message_list)>0:
            ai_prefix = self.personality.ai_message_prefix
        else:
            ai_prefix = ""


        # Details
        context_details = {
            "client_id":client_id,
            "conditionning":conditionning,
            "internet_search_infos":internet_search_infos,
            "internet_search_results":internet_search_results,
            "documentation":documentation,
            "documentation_entries":documentation_entries,
            "knowledge":knowledge,
            "knowledge_infos":knowledge_infos,
            "user_description":user_description,
            "discussion_messages":discussion_messages,
            "positive_boost":positive_boost,
            "negative_boost":negative_boost,
            "current_language":self.config.current_language,
            "fun_mode":fun_mode,
            "ai_prefix":ai_prefix,
            "extra":"",
            "available_space":available_space,
            "skills":skills_detials,
            "is_continue":is_continue,
            "previous_chunk":previous_chunk,
            "prompt":current_message.content
        }    
        if self.config.debug and not self.personality.processor:
            ASCIIColors.highlight(documentation,"source_document_title", ASCIIColors.color_yellow, ASCIIColors.color_red, False)
        # Return the prepared query, original message content, and tokenized query
        return context_details      


    # Properties ===============================================
    @property
    def start_header_id_template(self) -> str:
        """Get the start_header_id_template."""
        return self.config.start_header_id_template

    @property
    def end_header_id_template(self) -> str:
        """Get the end_header_id_template."""
        return self.config.end_header_id_template
    
    @property
    def system_message_template(self) -> str:
        """Get the system_message_template."""
        return self.config.system_message_template


    @property
    def separator_template(self) -> str:
        """Get the separator template."""
        return self.config.separator_template


    @property
    def start_user_header_id_template(self) -> str:
        """Get the start_user_header_id_template."""
        return self.config.start_user_header_id_template
    @property
    def end_user_header_id_template(self) -> str:
        """Get the end_user_header_id_template."""
        return self.config.end_user_header_id_template
    @property
    def end_user_message_id_template(self) -> str:
        """Get the end_user_message_id_template."""
        return self.config.end_user_message_id_template




    # Properties ===============================================
    @property
    def start_header_id_template(self) -> str:
        """Get the start_header_id_template."""
        return self.config.start_header_id_template

    @property
    def end_header_id_template(self) -> str:
        """Get the end_header_id_template."""
        return self.config.end_header_id_template
    
    @property
    def system_message_template(self) -> str:
        """Get the system_message_template."""
        return self.config.system_message_template


    @property
    def separator_template(self) -> str:
        """Get the separator template."""
        return self.config.separator_template


    @property
    def start_user_header_id_template(self) -> str:
        """Get the start_user_header_id_template."""
        return self.config.start_user_header_id_template
    @property
    def end_user_header_id_template(self) -> str:
        """Get the end_user_header_id_template."""
        return self.config.end_user_header_id_template
    @property
    def end_user_message_id_template(self) -> str:
        """Get the end_user_message_id_template."""
        return self.config.end_user_message_id_template




    @property
    def start_ai_header_id_template(self) -> str:
        """Get the start_ai_header_id_template."""
        return self.config.start_ai_header_id_template
    @property
    def end_ai_header_id_template(self) -> str:
        """Get the end_ai_header_id_template."""
        return self.config.end_ai_header_id_template
    @property
    def end_ai_message_id_template(self) -> str:
        """Get the end_ai_message_id_template."""
        return self.config.end_ai_message_id_template
    @property
    def system_full_header(self) -> str:
        """Get the start_header_id_template."""
        return f"{self.start_header_id_template}{self.system_message_template}{self.end_header_id_template}"
    @property
    def user_full_header(self) -> str:
        """Get the start_header_id_template."""
        return f"{self.start_user_header_id_template}{self.config.user_name}{self.end_user_header_id_template}"
    @property
    def ai_full_header(self) -> str:
        """Get the start_header_id_template."""
        return f"{self.start_user_header_id_template}{self.personality.name}{self.end_user_header_id_template}"

    def system_custom_header(self, ai_name) -> str:
        """Get the start_header_id_template."""
        return f"{self.start_user_header_id_template}{ai_name}{self.end_user_header_id_template}"

    def ai_custom_header(self, ai_name) -> str:
        """Get the start_header_id_template."""
        return f"{self.start_user_header_id_template}{ai_name}{self.end_user_header_id_template}"

