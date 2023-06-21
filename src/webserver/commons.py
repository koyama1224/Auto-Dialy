""" 
common variables
"""
from webserver.const import ConstValue as cv

from utils.log import setup_logger
from dotenv import load_dotenv
import os
from utils.const import WEATHER_URL, ENV_PATH, LOCATION_IP, GLOBAL_IP

# setup logger
logger = setup_logger(__name__, cv.LOG_PATH)

# environmental variables
load_dotenv(ENV_PATH)
weather_token = os.environ["WEATHER_TOKEN"]

server_name = os.environ["DATABASE_NAME"]
root_user = os.environ["ROOT_NAME"]
root_passwd = os.environ["ROOT_PASSWD"]

# secret
encrypt_method = os.environ["HASH_METHOD"]

# twitter
twitter_api_key = os.environ["TWITTER_API_KEY"]
twitter_api_key_secret = os.environ["TWITTER_API_KEY_SECRET"]

bearer_token = os.environ["TWITTER_BEARER_TOKEN"]
