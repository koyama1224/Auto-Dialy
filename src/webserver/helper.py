"""
in this module, helper functions are defined.

@author: minase_1224
"""
import codecs, sys
import functools
from flask import session, request, jsonify
import mysql.connector
from mysql.connector import Error
from .const import ConstValue as consts
import os
import datetime
from werkzeug.security import check_password_hash
import sys
from webserver.commons import (
    server_name,
    weather_token,
    root_user,
    root_passwd,
    encrypt_method,
    bearer_token,
    logger,
)
from utils.const import (
    WEATHER_URL,
    ENV_PATH,
    LOCATION_IP,
    GLOBAL_IP,
    SEARCH_RECENT,
    GET_IMAGE_URL,
)
import asyncio
import aiohttp
import ipaddress
import requests
import pke

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_response(msg: str, status: int, is_login: bool = False) -> dict:
    """make response with json format

    reponse body ex)
        {
            "UserInfo:{
                "YourIp": xxxxx,
                "loc": xxxx,
                "user_name": xxxx,
                "last_visit": 'xxxx-xx-xx'
            },
            "Response":{
                "status":xxx,
                "message": '',
            }
        }
    Args:
        msg (str): message to client such as error
        method (str): post, get and so on.
    """

    response_body = {}
    # if is_login is False:
    #     response_body["UserInfo"]

    response_body["Response"] = {"status": status, "message": msg}

    return response_body


def recv_and_log(func):
    """output log

    Args:
        func (function): callback function.

    Usage:
        as decorator,
        @app.route("/", methods=['POST'])
        @recv_and_log
        def hello():
            return "hello", 204
    """

    @functools.wraps(func)
    def wrap(*args, **keywords):
        # outputs
        logger.debug("receive requests from client")
        return func(*args, **keywords)

    return wrap


def login_required(func):
    """check login status

    Args:
        func (function): _description_

    Returns:
        function: _description_
    """

    @functools.wraps(func)
    def wrap(*args, **keywords):
        if session.get("username") is None:
            # not login status
            emsg = "you do not login into our service now. please login again."
            status = 403

            response = _make_response(emsg, status)

            return jsonify(response), status
        else:
            # login status
            return func(*args, **keywords)

    return wrap


def validate_user_info(func):
    """validate user information sent from client.

    Args:
        func (function): if succeed to validate,

    Returns:
        function: _description_
    """

    @functools.wraps(func)
    def wrap(*args, **keywords):
        try:
            user_info = request.form
            user_name = user_info["user_name"]
            login_passwd = user_info["passwd"]
            login_id = user_info["login_id"]
        except KeyError:
            emsg = "your request is invalid. please confirm your requests."
            status = 403
            response = _make_response(emsg, status)
            return jsonify(response), status
        else:
            return func(user_name, login_id, login_passwd)

    return wrap


def _create_server_connection(host_name: str, user_name: str, user_passwd: str):
    """
    Args:
        host_name (str):
        user_name (str):
        user_passwd (str):
    """
    connection = None
    try:
        connection = mysql.connector.connect(
            host=host_name, user=user_name, passwd=user_passwd, database=consts.db_name
        )
    except Error as err:
        logger.exception(err)

    return connection


def collate_user_information(user_id: str, passwd: str) -> bool:
    """check whether user is registerd or not.

    Args:
        user_id (str): _description_
        passwd (str): _description_

    Returns:
        bool: _description_
    """
    # collate user with login_id and login_passwd.
    # at first, connect to database by root account.
    # get connector to mysql
    connect = _create_server_connection(
        host_name=server_name, user_name=root_user, user_passwd=root_passwd
    )
    assert connect is not None
    ret = False
    try:
        cur = connect.cursor()

        # get records.
        sql = (
            "select user_name, login_passwd from authorization where login_id='%s';"
            % (user_id)
        )
        cur.execute(sql)
        ret = cur.fetchall()
        assert len(ret) == 1
        # collate requested password with secret password stored int db
        user_name, encrypt_passwd = ret[0]
        ret = check_password_hash(encrypt_passwd, passwd)
    except Exception as e:
        # record log
        logger.exception(e)
    finally:
        # closing process
        if cur is not None:
            cur.close()
        connect.close()
        return ret


def check_user_registration(login_id: str):
    """check whether login-id is registered or not.

    Args:
        login_id (str): unique strings in this system.
    """
    connect = _create_server_connection(
        host_name=server_name, user_name=root_user, user_passwd=root_passwd
    )
    assert connect is not None
    ret = False
    try:
        cur = connect.cursor()
        sql = (
            "select count(user_name) from authorization where login_id='%s'" % login_id
        )

        # execute sql
        cur.execute(sql)
        num_records = cur.fetchall()
        ret = True if num_records == 0 else False
    except Exception as err:
        logger.exception(err)

    finally:
        # closing process
        if cur is not None:
            cur.close()
        connect.close()
        return ret


def convert_ipaddr_local2global(ipaddr: str) -> str:
    """convert ipaddress from local one to global one.

    Args:
        ipaddr (str): local or global ipaddress

    Returns:
        str: only global ip-address(v4).
    """

    if ipaddress.IPv4Address(ipaddr).is_private is False:
        # not necessary
        return ipaddr

    try:
        # sync
        response = requests.get(GLOBAL_IP, timeout=(3.0, 5.0))
        response.raise_for_status()
        global_ip = response.json()["ip"]
    except Exception:
        return None
    else:
        return global_ip


async def get_location(client: aiohttp.ClientSession, global_ip: str) -> dict:
    """get geometric location from external api.

    Args:
        golbal_ip (str): global ip address (ipv4)

    Returns:
        dict: _description_
    """

    async with client.get(LOCATION_IP + str(global_ip), timout=5) as resp:
        return await resp.json()


async def get_local_and_weather(client: aiohttp.ClientSession, global_ip: str) -> dict:
    """_summary_

    Args:
        client (aiohttp.ClientSession): _description_
        global_ip (str): _description_

    Returns:
        dict: _description_
    """
    user_info = {}
    try:
        async with client.get(LOCATION_IP + str(global_ip), timeout=5) as resp:
            org_data = await resp.json()
            assert org_data is not None
            data = {
                "lat": org_data["lat"],
                "lon": org_data["lon"],
                "appid": weather_token,
            }
            user_info["location"] = org_data
        async with client.get(WEATHER_URL % data, timeout=5) as resp:
            resp_json = await resp.json()
            assert resp_json is not None
            weather_info = {
                "coord": resp_json["coord"],
                "weather": {
                    "type": resp_json["weather"][0]["main"],
                    "now-temp": resp_json["main"]["temp"],
                    "temp_max": resp_json["main"]["temp_max"],
                    "temp_min": resp_json["main"]["temp_min"],
                },
            }
            user_info["weather"] = weather_info
    except Exception as e:
        logger.exception(e)
        user_info["msg"] = "error"

    return user_info


def bearer_oauth(r):
    """method required by bearer token authentication

    Args:
        r (_type_): _description_
    """

    r.headers["Authorization"] = f"Bearer {bearer_token}"
    r.headers["User-Agent"] = "v2UserTweetsPython"
    return r


async def connect_to_endpoint(client: aiohttp.ClientSession, params: dict):
    try:
        test_tweet_ids = []
        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "User-Agent": "v2UserTweetsPython",
        }
        async with client.get(
            SEARCH_RECENT, params=params, headers=headers, timeout=5
        ) as resp:
            org_data = await resp.json()
            assert org_data is not None
            test_tweet_ids = [od["id"] for od in org_data["data"]]
    except Exception as r:
        print(r)
    finally:
        return test_tweet_ids


def retrieve_keyword(mp_queue):
    """retrieve keyword from diary."""

    while True:
        ret = mp_queue.get(timeout=1)
