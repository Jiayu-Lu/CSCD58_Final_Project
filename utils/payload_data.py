from enum import Enum

class LoginStatus(Enum):
    SUCCESS = (1 << 0)
    FAILED = (1 << 1)
    GUEST = (1 << 2)
    HOST = (1 << 3)
    ROOT = (1 << 4)

class Actions(Enum):
    SUDO = (1 << 0)
    OPEN_SHELL = (1 << 1)
    CLOSE_SHELL = (1 << 2)
    CREATE_FILE = (1 << 3)
    FILE_TRANSFER = (1 << 4)
    ACCESS_CONTROL_FILE = (1 << 5)

    ## HOT Actions
    ACCESS_RESTRICTED_RES = (1 << 6)
    MODIFY_RESTRICTED_RES = (1 << 7)

# Definitions
LOGIN_KEYWORD = "login"

def create_action_data(action):
    msg = ""
    for a in Actions:
        if a.value & action:
            msg += a.name + " "
    
    return msg.rstrip()



def create_login_data(login):
    msg = LOGIN_KEYWORD + " "

    if login & LoginStatus.SUCCESS.value:
        msg += LoginStatus.SUCCESS.name + " "
    else:
        msg += LoginStatus.FAILED.name + " "
    
    if login & LoginStatus.ROOT.value:
        msg += LoginStatus.ROOT.name + " "

    if login & LoginStatus.HOST.value:
        msg += LoginStatus.HOST.name
    else:
        msg += LoginStatus.GUEST.name
    
    return msg
