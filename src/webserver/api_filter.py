"""
common function for every requests.


using flask and extension function, 
"""
from utils.log import setup_logger
from webserver.const import ConstValue as cv
from flask import (
    current_app,
    jsonify,
    Flask,
    request,
    session,
    redirect,
    url_for,
    render_template,
    send_from_directory,
)
from functools import wraps
from werkzeug.exceptions import NotFound, BadRequest, InternalServerError
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import ipaddress
from utils.const import WEATHER_URL, ENV_PATH, LOCATION_IP, GLOBAL_IP
from webserver.db import create_server_connection
from webserver.user_exceptions import NoUserException
import datetime
import functools

# set logger
logger = setup_logger(__name__, cv.LOG_PATH)

# make flask server
app = Flask(__name__)

# load env file
load_dotenv(ENV_PATH)
weather_token = os.environ["WEATHER_TOKEN"]

# user information
root_user = os.environ["ROOT_NAME"]
root_passwd = os.environ["ROOT_PASSWD"]

# app key
app.secret_key = os.environ["SECRET_KEY"]

# database info
db_name = os.environ["DATABASE_NAME"]
encrypt_method = os.environ["HASH_METHOD"]


def make_result(method: str, message: str) -> dict:
    """this function is template format for replying to client requests.

    Args:
        method (str): "post", "get" and so on.
        message (str): description for your status.
    Returns:
        _type_: _description_
    """

    result = {"message": message, "method": method, "app_name": current_app.name}
    return result


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static/img/"),
        "favicon.ico",
    )


def record_log(func):
    """record log into file.
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


@app.before_request
def before_request():
    """
    manage session
    """
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=1)
    session.modified = True


def login_common(func):
    """common process for checking login status.

    Args:
        func (callback function)
    Returns:
        wrapper
    """

    @functools.wraps(func)
    def wrap(*args, **keywords):
        if session.get("username") is None:
            # if not login
            # return redirect(url_for("login"))
            return jsonify({"message": "not login"}), 404
        else:
            return func(*args, **keywords)

    return wrap


@app.route("/home", methods=["GET"])
def home():
    """first response to user.

    Returns: templates
    """
    return render_template("home.html")


def validate_user_info(func):
    """_summary_

    Args:
        func (_type_): _description_

    Returns:
        _type_: _description_
    """

    @functools.wraps(func)
    def wrap(*args, **keywords):
        try:
            user_info = request.json["user_info"]
            user_name = user_info["user_name"]
            user_passwd = user_info["passwd"]
            login_id = user_info["login_id"]
        except KeyError:
            return jsonify({"status": "error"}), 400
        else:
            return func(user_name, login_id, user_passwd)

    return wrap


@app.route("/login", methods=["POST"])
@validate_user_info
def login_proc(user_name: str, login_id: str, user_passwd: str):
    """process for login

    this process is divided into two part.

    1. flask login are made to be set with secret key.

    Args:
        user_name (str): _description_
        login_id (str): _description_
        user_passwd (str): _description_

    Returns:
        _type_: _description_
    """
    # get user information

    try:
        check_user_exists(user_id=login_id, passwd=user_passwd)
    except NoUserException as e:
        return jsonify({"status": "error", "message": str(e)}), 401
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    if "username" not in session:
        session["username"] = user_name
        session["diary"]
    return jsonify({"status": "success"}), 204


@app.route("/register", methods=["POST"])
@validate_user_info
def register_user(user_name: str, login_id: str, user_passwd: str):
    """
    this function is called when client try to create new user account.

    1. verify whether user(login id) is not registerd.
    2. if not, transaction is conducted.
        - create query into user table
        - create query into authorization table with encrypted password.
    """
    # validate user.
    ret = _check_unique_login_id(user_name)

    if ret is False:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "this user name is already registered. please confirm.",
                }
            ),
            401,
        )
    else:
        # {user_name} is not existed in user database
        # transaction start
        con = create_server_connection(
            host_name=db_name, user_name=root_user, user_passwd=root_passwd
        )
        try:
            cur = con.cursor()
            regist_time = datetime.datetime.utcnow().date()
            user_sql = "insert into user values (null, '%s', '%s', '%s', null);"
            ret = cur.execute(user_sql % (user_name, regist_time, regist_time))
            auth_sql = (
                "insert into authorization values ('%s', '%s', '%s', '%s', '%s');"
            )
            ret = cur.execute(
                auth_sql
                % (
                    user_name,
                    login_id,
                    generate_password_hash(user_passwd),
                    regist_time,
                    regist_time,
                )
            )
            con.commit()

        except Exception as e:
            logger.exception(e)
            con.rollback()
            return jsonify({"status": "failed"}), 500
        else:
            # create session
            if "username" not in session:
                session["username"] = user_name
            cur.close()
            con.close()
            return jsonify({"status": "success"}), 204


@app.route("/fixconfig", methods=["GET", "POST"])
@login_common
def fix_config():
    """
    this function is used to change passwd and
    """
    # easily return "hello connection."
    # session is alived.
    return jsonify({"message": "session test is succeed"}), 204


@app.route("/logout", methods=["GET"])
@login_common
def logout_proc():
    try:
        logger.debug(session["username"])
        session.pop("username", None)
    except Exception:
        logger.error("erorr occured. check log.")
    return jsonify({"status": "logout success"}), 204


def check_user_exists(user_id: str, passwd: str) -> bool:
    """
    this function is to validate json.

    to test this function, it is necessary to add query into user table.
    """

    # collate user name and password
    # connect to database by root account
    con = create_server_connection(
        host_name=db_name, user_name=root_user, user_passwd=root_passwd
    )
    try:
        cur = con.cursor()
        # get queries corresponding to user_name
        sql = (
            "select user_name, login_passwd from authorization where login_id='%s';"
            % (user_id)
        )
        cur.execute(sql)
        ret = cur.fetchall()
        assert len(ret) == 1
        user_name, encrypt_passwd = ret[0]
        assert check_password_hash(encrypt_passwd, passwd)
    except Exception as err:
        # others error such as connection error.
        logger.exception(err)
        raise Exception("internal error has happend.")
    finally:
        cur.close()
        con.close()
        return ret


def _check_unique_login_id(user_id: str):
    """
    check whether login-id is already utilized in this system.

    Args:
        user_id (str):

    Returns:
        ret (bool):
            true -> not registerd.
            false -> already registered.
    """
    con = create_server_connection(
        host_name=db_name, user_name=root_user, user_passwd=root_passwd
    )
    ret = False

    try:
        cur = con.cursor()

        sql = "select count(user_name) from authorization where login_id='%s'" % user_id
        cur.execute(sql)
        ret = cur.fetchall()
        if ret[0] == 0:
            ret = True
    except Exception as err:
        logger.exception(err)
    finally:
        try:
            cur.close()
        except Exception:
            pass
        con.close()
        return ret


@app.route("/config-change", methods=["POST"])
def set_config():
    """
    Args:
        None
    Returns:
        None

    procedure:
        1. validate config
        2. get lock for editing config file.
        3.
    """

    # validate config using json-schema


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
        "coord": ret["coord"],
        "weather": {
            "type": ret["weather"][0]["main"],
            "now-temp": ret["main"]["temp"],
            "temp_max": ret["main"]["temp_max"],
            "temp_min": ret["main"]["temp_min"],
        },
    }

    if ret is None:
        return 404
    else:
        return make_result(method="GET", message=ret)


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
            print(response.json())
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
            "appid": weather_token,
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
