#!/usr/bin/python

import ConfigParser
import logging
import os 
import sys
import threading
from Queue import Queue
import time
import json
import hashlib
import pycurl
import StringIO


LOG_FILE        = 'file'
OFFSET_FILE     = 'file'
REPORT_POLL     = 2
RESEND_COUNT    = 3
MAX_LINE_COUNT  = 20

ALARM_FLAG      = False
ALARM_FILE      = 'file'
ALARM_TIME      = 30
ALARM_COUNT     = 12

RUN_LEVEL       = 'INFO'
RUN_LOG         = 'file'

def get_log_offset(logoff):
    try:
        f = open(OFFSET_FILE, 'r')
        try:
            lines = f.readlines()
            for line in lines :
                splits = line.split(":")
                if len(splits) == 2 and splits[0] == "tstamp":
                    logoff['tstamp'] = int(splits[1])
                elif len(splits) == 2 and splits[0] == "offset":
                    logoff['offset'] = int(splits[1])
                elif len(splits) == 2 and splits[0] == "linesc":
                    logoff['linesc'] = int(splits[1])
            # end for
        finally:
            f.close()
    except IOError:
        logging.error("read offset_file error")
        logoff['tstamp'] = 0
        logoff['offset'] = 0
        logoff['linesc'] = 0
# end get_log_offset

def set_log_offset(logoff, tstamp, linesc, offset):
    logoff['tstamp'] = tstamp
    logoff['linesc'] = linesc
    logoff['offset'] = offset
    
    try:
        f = open(OFFSET_FILE, 'wb')
        try:
            ostr = "tstamp:%d\nlinesc:%d\noffset:%d" % (tstamp, linesc, offset)
            f.write(ostr)
        finally:
            f.close()
    except IOError:
        logging.error("write offset_file error")
# end set_log_offset

def set_alarm_flag(timestamp, delta, flag):
    try:
        f = open(ALARM_FILE, 'wb')
        try:
            ostr = "%d %d %d" % (timestamp, delta, flag)
            f.write(ostr)
        finally:
            f.close()

    except IOError:
        logging.error("write alarm_file error")
        return
# end set_alarm_flag

def send_http_param(param) :
    start_time = time.time()
    c = pycurl.Curl()
    buf = StringIO.StringIO()
    code = 0
    try :
        c.setopt(pycurl.URL, API_URL)
        c.setopt(pycurl.WRITEFUNCTION, buf.write)
        c.setopt(pycurl.POSTFIELDS, str(param))
        c.setopt(pycurl.TIMEOUT, 1)
        c.setopt(pycurl.NOSIGNAL, True)
        
        c.perform()
        code = c.getinfo(c.HTTP_CODE)
    except pycurl.error, error:
        errno, errstr = error
        logging.warning("Error. no:%d str:%s" % (errno, errstr))
    finally:
        buf.close()
        c.close()
    end_time = time.time()
    logging.debug("send_http_param %f %f %f len(param):%d" % (start_time, end_time, end_time-start_time, len(param)))
    return code
#end send_http_param

def send_log_content(sjson) :
    # get current time
    current_ts = int(time.time())

    # build md5
    secret = "46a654742f93ac6be5b3645c74d2574f"
    content = str(current_ts) + secret + sjson + str(current_ts)
    md5 = hashlib.md5()
    md5.update(content)
    sign = md5.hexdigest()

    ########## POST request
    param = "time=" + str(current_ts)
    param += "&random=" + str(current_ts)
    param += "&sign=" + str(sign)
    param += "&sJson="+ str(sjson)

    # send and resend data
    sendc = 0;
    while (sendc < RESEND_COUNT) :
        if send_http_param(param) == 200 :
            break
        else :
            sendc += 1
            logging.info("resend time count:%d" % sendc)
    # end while
# end send_log_content

def put_queue_content(conqueue, session, sjson) :
    sessionmode = hash(session)%CONSUMER_COUNT
    logging.debug("session:%s hash:%d sessionmode:%d" % (session, hash(session), sessionmode))
    conqueue[sessionmode].put(sjson)
# end put_queue_content

def put_queue_content_batch(conqueue, watchdict) :
    for k,v in watchdict.items() :
        sjson = json.dumps(v)
        put_queue_content(conqueue, k, sjson)
    watchdict.clear()
# end put_queue_content_batch 

def get_line_json(conqueue, sjson, watchdict, alarmdict) :
    maxcount  = -1
    timestamp = 0
    try :
        json_obj = json.loads(sjson)
        if (json_obj.has_key('_type') == False or
                json_obj.has_key('session') == False or 
                json_obj.has_key('timestamp') == False) :
            return maxcount, timestamp
        
        _type       = json_obj['_type']
        timestamp   = json_obj['timestamp'] 
        session     = json_obj['session']
        if (_type == 'v2.edgePullStart' or _type == 'v2.edgePullStop' or
                _type == 'v2.edgePushStart' or _type == 'v2.edgePushStop' or
                _type == 'v2.edgeBufferStart' or _type == 'v2.edgeBufferStop' or
                _type == 'v2.edgeBackSource') :
            put_queue_content(conqueue, session, sjson)
            maxcount = 0
        elif (_type == 'v2.edgePullWatch' or _type == 'v2.edgePushWatch'):
            if (json_obj.has_key('name') and json_obj.has_key('protocolType') and
                    json_obj.has_key('timestamp') and json_obj.has_key('session') and
                    json_obj.has_key('serverIP') and json_obj.has_key('clientIP') and
                    json_obj.has_key('host') and json_obj.has_key('body') ) :
                body = json_obj["body"]
                body['timestamp'] = json_obj['timestamp']
                
                if watchdict.has_key(session) :
                    watchdict[session]["body"].append(body)
                else :
                    tmpdic = {}
                    tmpdic['_type']        = json_obj['_type']
                    tmpdic['name']         = json_obj['name']
                    tmpdic['protocolType'] = json_obj['protocolType']
                    tmpdic['timestamp']    = json_obj['timestamp']
                    tmpdic['serverIP']     = json_obj['serverIP']
                    tmpdic['clientIP']     = json_obj['clientIP']
                    tmpdic['session']      = json_obj['session']
                    tmpdic['host']         = json_obj['host']
                    tmpdic['body']         = [body]
                    watchdict[session] = tmpdic
                maxcount = len(watchdict[session]["body"])

        if (ALARM_FLAG) :
            if ( _type == 'v2.edgePullStop' ) :
                body = json_obj["body"]
                statusCode = -1;
                if (body.has_key("statusCode")) :
                    statusCode = long(body['statusCode'])
                if (statusCode != 0 and statusCode != 40 and statusCode != 41 and
                        statusCode != 43 and statusCode != 60 and statusCode != 61) :
                    alarmdict["stop"] += 1
                elif (_type == 'v2.edgeBackSource' or _type == 'v2.edgePullStart') :
                    alarmdict["other"] += 1
        # end ALARM_FLAG
    except ValueError :
        logging.error("get json error")
    return maxcount, timestamp
# end get_line_json

def get_log_content(logoffset, conqueue, alarmdict):
    ttstmap = logoffset['tstamp']
    tlinesc = logoffset['linesc']
    toffset = logoffset['offset']

    try :
        f = open(LOG_FILE, 'r')

        # find first timestamp
        ftstamp = 0
        try :
            while True:
                line = f.readline()
                if (line != "") :
                    str_list = line.split("EDGE")
                    if (len(str_list) == 3) :
                        json_obj = json.loads(str_list[1])
                        if json_obj.has_key('timestamp') == True :
                            ftstamp = json_obj['timestamp']
                            break
                else :
                    logging.info("Empty log file")
                    break
            # end while
        finally :
            if (ftstamp > ttstmap or ftstamp==0) :
                set_log_offset(logoffset, ftstamp, 0, 0)
                logging.info("Reset offset file %d" % ftstamp)
                return
            else :
                logging.info("Start ftstamp:%d ttstmap:%d linesc:%d offset:%d" % (ftstamp, ttstmap, tlinesc, toffset))

        
        # read log data
        f.seek(toffset, 0)
        watchdict = {}
        try :
            lines = f.readlines()
            for line in lines :
                # update offset
                tlinesc += 1
                toffset += len(line)

                # parse json
                str_list = line.split("EDGE")
                if (len(str_list) != 3) :
                    continue

                maxcount,timestamp = get_line_json(conqueue, str_list[1], watchdict, alarmdict)
                # update offset
                if (timestamp > 0) :
                    ttstmap = timestamp
                if (maxcount >= MAX_LINE_COUNT) :
                    loggin.info("MAX the queue len(watch):%d" % (len(watchdict)))
                    put_queue_content_batch(conqueue, watchdict)
                    set_log_offset(logoffset, ttstmap, tlinesc, toffset)
            # end for
        finally :
            logging.info("Finally tstamp:%d linesc:%d offset:%d" % (ttstmap, tlinesc, toffset))
            put_queue_content_batch(conqueue, watchdict)
            set_log_offset(logoffset, ttstmap, tlinesc, toffset)
            f.close()
    except:
        logging.error("not found log file or other unknown error")
#end get_log_content

class Producer(threading.Thread) :
    def __init__(self, conqueue) :
        threading.Thread.__init__(self)
        self.conqueue   = conqueue
        self.sleep_time = 0.5    

    def run(self) :
        logging.info("Producer thread started!")
        
        logoffset = {'tstamp':0, 'linesc':0, 'offset':0}
        get_log_offset(logoffset)
        logging.info("INIT tstamp:%d linesc:%d offset:%d" % (logoffset['tstamp'], logoffset['linesc'], logoffset['offset']))

        sendtime = 0
        alarmtime   = time.time()
        alarmdict   = {}
        alarmdict["stop"] = 0
        alarmdict["other"] = 0
        while True:
            try :
                if (sendtime >= REPORT_POLL) :
                    get_log_content(logoffset, self.conqueue, alarmdict) 
                    sendtime = 0
                else :
                    sendtime += self.sleep_time
                
                if (ALARM_FLAG) :
                    currentime = time.time()
                    deltatime  = (currentime - alarmtime)
                    if ( deltatime >= ALARM_TIME ) :
                        logging.info("Alarm currentime:%d deltatime:%d stopcount:%d othercount:%d" % (currentime, deltatime, alarmdict["stop"], alarmdict["other"]))
                        if ( alarmdict["stop"] >= ALARM_COUNT and
                                alarmdict["other"] == 0) :
                            set_alarm_flag(currentime, deltatime, 0)
                        else :
                            set_alarm_flag(currentime, deltatime, 1)
                            alarmtime = currentime
                            alarmdict["stop"] = 0
                            alarmdict["other"] = 0
                # end ALARM_FLAG
            finally :
                time.sleep(self.sleep_time)
        # end while 
        logging.info("Producer thread finished!")
# end class Producer 

class Consumer(threading.Thread) :
    def __init__(self, connumber, queue) :
        threading.Thread.__init__(self)
        self.queue      = queue
        self.connumber  = connumber 
        self.sleep_time = 0.5    

    def run(self) :
        logging.info("Consumer thread started! connumber:%d" % self.connumber)
        ltime =time.time()
        while True:
            try :
                while (not self.queue.empty()) :
                    logging.debug("Consumer thread len(queue):%d connumber:%d" %(self.queue.qsize(), self.connumber))
                    sjson = self.queue.get()
                    send_log_content(sjson)
            finally :
                time.sleep(self.sleep_time)
                ctime = time.time()
                if (ctime - ltime > 30) :
                    ltime = ctime
                    logging.info("Consumer thread heart! connumber:%d" % self.connumber)
                    
        logging.info("Consumer thread finished! connumber:%d" % self.connumber)
# end class Consumer 

def get_conf_file(CONF_FILE) :
    config = ConfigParser.ConfigParser()
    config.read(CONF_FILE)

    global LOG_FILE
    global OFFSET_FILE
    global REPORT_POLL
    global RESEND_COUNT
    global MAX_LINE_COUNT
    global API_URL
    global CONSUMER_COUNT
    LOG_FILE        = config.get("system", "log_file")
    OFFSET_FILE     = config.get("system", "offset_file")
    REPORT_POLL     = int(config.get("system", "report_poll"))
    RESEND_COUNT    = int(config.get("system", "resend_count"))
    MAX_LINE_COUNT  = int(config.get("system", "max_line_count"))
    API_URL         = config.get("system", "api_url")
    CONSUMER_COUNT  = int(config.get("system", "consumer_count"))
    
    global ALARM_FLAG
    global ALARM_FILE
    global ALARM_TIME
    global ALARM_COUNT
    if (config.get("alarm", "alarm_flag") == "on") :
        ALARM_FLAG = True
    ALARM_FILE      = config.get("alarm", "alarm_file") 
    ALARM_TIME      = int(config.get("alarm", "alarm_time"))
    ALARM_COUNT     = int(config.get("alarm", "alarm_count"))
    
    global RUN_LEVEL
    global RUN_LOG
    RUN_LEVEL       = config.get("logging", "run_level")
    RUN_LOG         = config.get("logging", "run_log")
# get_conf_file

def _main_() :
    CONF_FILE = './report_log.conf'
    if (len(sys.argv) == 1):
        abspath = os.path.abspath(sys.argv[0])
        abspath = os.path.dirname(abspath)+"/"
        CONF_FILE = abspath+"report_log.conf"
    elif (len(sys.argv) == 2):
        CONF_FILE = sys.argv[1]
    print CONF_FILE
    get_conf_file(CONF_FILE)
    
    # logging
    if (RUN_LEVEL == "INFO") :
        logging.basicConfig(level=logging.INFO,
                format='%(asctime)s %(filename)s:%(lineno)-3d %(levelname)-7s %(message)s',
                datefmt='%Y/%m/%d %H:%M:%S',
                filename=RUN_LOG,
                filemode='a')
    elif (RUN_LEVEL == "ERROR") :
        logging.basicConfig(level=logging.ERROR,
                format='%(asctime)s %(filename)s:%(lineno)-3d %(levelname)-7s %(message)s',
                datefmt='%Y/%m/%d %H:%M:%S',
                filename=RUN_LOG,
                filemode='a')
    else :
        logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s:%(lineno)-3d %(levelname)-7s %(message)s',
                datefmt='%Y/%m/%d %H:%M:%S',
                filename=RUN_LOG,
                filemode='a')
    
    console = logging.StreamHandler()
    #console.setLevel(logging.INFO)
    console.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)s: %(levelname)-7s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

    consumer_queue = {}
    for i in range(CONSUMER_COUNT) :
        consumer_queue[i] = Queue()
    
    threads = []
    # create producer
    producer = Producer(consumer_queue)
    producer.start()
    threads.append(producer)

    # create consumer
    for i in range(CONSUMER_COUNT) :
        consumer = Consumer(i, consumer_queue[i])
        consumer.start()
        threads.append(consumer)
    logging.info("Create %d consumer" %(CONSUMER_COUNT))
        
    for t in threads:
        t.join()
        logging.info("Exiting Main Thread")
# end _main_

if __name__ == "__main__" :
    _main_()
# end __main__
