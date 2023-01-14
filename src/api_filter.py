"""
common function for every requests.
"""
from utils.log import setup_logger
from webserver.const import ConstValue as cv
from flask import current_app, jsonify, Flask, request
from functools import wraps
from werkzeug.exceptions import NotFound,BadRequest,InternalServerError
import requests
from dotenv import load_dotenv
import os 
import ipaddress
from utils.const import WEATHER_URL, ENV_PATH, LOCATION_IP, GLOBAL_IP

# set logger
logger = setup_logger(__name__, cv.LOG_PATH)

# make flask server
app = Flask(__name__)

# load env file
load_dotenv("/home/src/credential/.env")
weather_token = os.environ['WEATHER_TOKEN']


def make_result(method, message: str):
    """
    this function make result towards to requests.

    Args:
        None
    Returns:
        None
    """

    result = {"message": message, "method": method, "app_name": current_app.name}
    return result

def record_log(func):
    """
    this function is to be decorator.

    Args:
        func (function object):
    Returns:
        wrap 
    """
    @wraps(func)
    def wrap(*args, **keywords):
        # output log
        logger.debug("receive requests from client")
        # do function
        return func(*args, **keywords)
    return wrap


@app.route("/get-my-info", methods=["GET"])
@record_log
def get_my_info():
    """
    get my information saved in this system.

    this function is basically used for communication test.
    """
    message = "hello flask server"
    ret = make_result("GET", message)
    return jsonify(ret), 204

# error handler : http status code : 404
@app.errorhandler(NotFound)
@record_log
def error_handle_not_found():
    """
    for erro code : 404 not found url.
    """
    message = "url is not correct. please confirm your url kindly"
    ret = make_result("GET", message)
    return jsonify(ret), 404

@app.route("/get-today-info")
@record_log
def get_today_info():
    """
    this function obtain following information.
        1. weather (including temprature, )
        2. 
    """

    # get weather 
    weather_url = "https://weather.tsukumijima.net/api/forecast/city/440010"
    logger.debug("accessed ip address : %s" % (request.remote_addr))
    msg = None
    try:
        response = requests.get(weather_url)
        response.raise_for_status()
        msg = response.json()
    except requests.exceptions.RequestException as e:
        msg = "error in getting weather information"
    
    # make response
    ret = make_result(method="GET", message=msg)

    return ret

@app.route("/test-loc")
def get_weather_on_location():
    # get ip address
    ip_addr = request.remote_addr
    ret = _get_weather(ip_addr)

    # arrange data
    result = {
        "coord":ret["coord"],
        "weather":{
            "type": ret["weather"][0]["main"],
            "now-temp": ret["main"]["temp"],
            "temp_max": ret["main"]["temp_max"],
            "temp_min": ret["main"]["temp_min"]
        } 
    }
    

    if ret is None:
        return 404
    else:
        return make_result(method="GET", message=result)


def _get_weather(ip_addr: str):
    """
    this function is utilized to get geometric location of client.


    processing flow:
        1. get global ip address. (when loop back address.)
        using https://api.ipify.org (https://github.com/rdegges/ipify-api)
    """
    msg = ""
    try:
        # get global ip addr
        if ipaddress.IPv4Address(ip_addr).is_private is True:
            response = requests.get(GLOBAL_IP, timeout=(3.0, 5.0))
            response.raise_for_status()
            global_ip = response.json()["ip"]
            logger.info("get my ip address %s" % str(global_ip))
        else:
            global_ip = ip_addr
        # get location json format. 
        response = requests.get(LOCATION_IP + str(global_ip), timeout=(3.0, 5.0))
        response.raise_for_status()
        logger.info("get your location %s" % response.json())

        # get weather information
        data = {
            "lat": response.json()["lat"],
            "lon": response.json()["lon"],
            "appid": weather_token
        }
        response = requests.get(WEATHER_URL % data, timeout=(3.0, 5.0))
        response.raise_for_status()
        
    except requests.exceptions.RequestException as e:
        logger.exception(e)
        return None
    else:
        return response.json()

    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10002)
