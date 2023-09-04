
# Press the green button in the gutter to run the script.
from file_capture import FileCapture

if __name__ == '__main__':
    #capture = FileCapture("E:/CSNA-E培训/packets/sql_worm.cap")
    capture = FileCapture("D:/pcap/http.cap")
    capture.scapyTest()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
