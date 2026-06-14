from enum import Enum

class TCPState():
    NONE = 0
    CLOSED = 1
    SYN_SENT = 2
    SYN_RECEIVED = 3
    ESTABLISHED = 4
    FIN_WAIT_1 = 5
    FIN_WAIT_2 = 6
    TIME_WAIT = 7
