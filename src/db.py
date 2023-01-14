"""
this program must be conducted before using Auto-Diary.

1. create sql database.
"""
import mysql.connector
from mysql.connector import Error
import pandas as pd
from utils.log import setup_logger
from webserver.const import ConstValue as cv

logger = setup_logger(__name__, cv.LOG_PATH)


def create_server_connection(host_name: str, user_name: str, user_passwd: str):
    """
    Args:
        host_name (str):
        user_name (str):
        user_passwd (str):
    """
    connection = None
    try:
        connection = mysql.connector.connect(
            host=host_name, user=user_name, passwd=user_passwd, database="auto-diary-db"
        )
    except Error as err:
        logger.exception(err)

    return connection


if __name__ == "__main__":
    con = create_server_connection("db-mysql-1", "tester", "tester")
    try:
        cur = con.cursor()
        sql = "show tables;"
        cur.execute(sql)
    except Exception as e:
        logger.exception(e)
    finally:
        logger.debug("succeed to connect to ")

        try:
            if con is None:
                pass
            else:
                con.close()
        except:
            logger.warning("dangerous phanomena happens")
