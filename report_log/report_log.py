#!/usr/bin/python
# edge log monitor  
import os
import sys
import json
import time
import httplib
import urllib
import hashlib
import pycurl
import StringIO

CONF = {}
CONF["report_poll"]     = 10
CONF["log_file"]        = '/home/MOMO/servers/nginx-flv/logs/rtmp/rtmp.log'
CONF["resend_count"]    = 3
CONF["max_line_count"]  = 50
CONF["api_url"]         = "https://live-api.immomo.com/ext/edge/report"

CONF["offset_file"]     = './log_offset.txt'

CONF["alarm_flag"]      = False
CONF["alarm_file"]      = './alarm_flag.txt'
CONF["alarm_time"]      = 300
CONF["alarm_count"]     = 12

SLEEP_TIME  = 1
def get_log_conf(CONF_FILE):
    print "CONF_FILE :%s" % CONF_FILE
    try:
        f = open(CONF_FILE, 'r') 
        try: 
            lines = f.readlines()
            for line in lines :  
                commds = line.split(";")
                if len(commds) != 2:
                    continue
                
                splits = commds[0].split("=")
                if len(splits) == 2 and splits[0] == "report_poll":
                    CONF["report_poll"]     = splits[1]
                elif len(splits) == 2 and splits[0] == "log_file":
                    CONF["log_file"]        = splits[1]
                elif len(splits) == 2 and splits[0] == "resend_count":
                    CONF["resend_count"]    = splits[1]
                elif len(splits) == 2 and splits[0] == "max_line_count":
                    CONF["max_line_count"]  = splits[1]
                elif len(splits) == 2 and splits[0] == "api_url":
                    CONF["api_url"]         = splits[1]
                elif len(splits) == 2 and splits[0] == "offset_file":
                    CONF["offset_file"]     = splits[1]
                elif len(splits) == 2 and splits[0] == "alarm_flag":
                    if (splits[1] == "on") :
                        CONF["alarm_flag"]  = True
                    else :
                        CONF["alarm_flag"]  = False
                elif len(splits) == 2 and splits[0] == "alarm_file":
                    CONF["alarm_file"]      = splits[1]
                elif len(splits) == 2 and splits[0] == "alarm_time":
                    CONF["alarm_time"]      = splits[1]
                elif len(splits) == 2 and splits[0] == "alarm_count":
                    CONF["alarm_count"]     = splits[1]
            # end for
        finally:
            f.close();
            return True
    except IOError:
        return False
# end get_log_conf

def get_log_offset(logoff):
    try:
        f = open(CONF["offset_file"], 'r') 
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
            f.close();
    except IOError:
        logoff['offset'] = 0 
        logoff['linesc'] = 0
# end get_log_offset

def set_log_offset(logoffset, tstamp, linesc, offset):
    logoffset['tstamp'] = tstamp
    logoffset['linesc'] = linesc
    logoffset['offset'] = offset

    try:
        f = open(CONF["offset_file"], 'wb')
        try:
            ostr = "tstamp:%d\nlinesc:%d\noffset:%d" % (tstamp, linesc, offset)
            f.write(ostr)
        finally:
            f.close()
    except IOError:
        return
# end set_log_offset

def set_alarm_flag(timestamp, delta, flag):
    try:
        f = open(CONF["alarm_file"], 'wb')
        try:
            ostr = "%d %d %d" % (timestamp, delta, flag)
            f.write(ostr)
        finally:
            f.close()

    except IOError:
        return
# end set_alarm_flag

def send_http_param(param) :
    #start_time = time.time()
    c = pycurl.Curl()
    buf = StringIO.StringIO()
    code = 0
    try :
        c.setopt(c.URL, CONF["api_url"])
        c.setopt(c.WRITEFUNCTION, buf.write)
        c.setopt(c.POSTFIELDS, str(param))
        c.setopt(c.TIMEOUT, 1)
    
        c.perform()
        code = c.getinfo(c.HTTP_CODE)
    except pycurl.error, error:
        errno, errstr = error
        print "Error. no:%d str:%s" % (errno, errstr)
    finally:
        buf.close()
        c.close()
    #end_time = time.time()
    #print "send_http_param %d %d %d" % (start_time, end_time, end_time-start_time)
    return code
#end send_http_param

watch_dic = {}
alarm_dic = {}
alarm_dic["stop"] = 0
alarm_dic["other"] = 0
def get_line_json(line) :
    str_list = line.split("EDGE")
    if len(str_list) == 3:
        #print "linesize:%d jsonsize:%d" % (len(line), len(str_list[1]))
        json_obj = json.loads(str_list[1])
        if json_obj.has_key('_type') == False or json_obj.has_key('timestamp') == False:
            return 0
        
        _type = json_obj['_type']
        timestamp = json_obj['timestamp']
        if (_type == 'v2.edgePullStart' or _type == 'v2.edgePullStop' or 
                _type == 'v2.edgePushStart' or _type == 'v2.edgePushStop' or
                _type == 'v2.edgeBufferStart' or _type == 'v2.edgeBufferStop' or
                _type == 'v2.edgeBackSource') :
            send_log_content(str_list[1])
        elif (_type == 'v2.edgePullWatch' or _type == 'v2.edgePushWatch'):
            if (json_obj.has_key('name') and json_obj.has_key('protocolType') and 
                    json_obj.has_key('timestamp') and json_obj.has_key('session') and
                    json_obj.has_key('serverIP') and json_obj.has_key('clientIP') and
                    json_obj.has_key('host') and json_obj.has_key('body') and
                    json_obj.has_key('_type')) :
                session = json_obj['session']
                body = json_obj["body"]
                body['timestamp'] = json_obj['timestamp']
                
                if watch_dic.has_key(session) :
                    watch_dic[session]["body"].append(body)
                else :
                    tmp_dic = {}
                    tmp_dic['_type']        = json_obj['_type']
                    tmp_dic['name']         = json_obj['name']
                    tmp_dic['protocolType'] = json_obj['protocolType']
                    tmp_dic['timestamp']    = json_obj['timestamp']
                    tmp_dic['serverIP']     = json_obj['serverIP']
                    tmp_dic['clientIP']     = json_obj['clientIP']
                    tmp_dic['session']      = json_obj['session']
                    tmp_dic['host']         = json_obj['host']
                    tmp_dic['body']         = [body]

                    watch_dic[session] = tmp_dic
        # end if 

        # 0 40 41 43 60 61 
        # add alarm 
        if (CONF["alarm_flag"]) :
            if ( _type == 'v2.edgePullStop' ) :
                body = json_obj["body"] 
                statusCode = -1;
                if (body.has_key("statusCode")) :
                    statusCode = long(body['statusCode'])
                if (statusCode != 0 and statusCode != 40 and statusCode != 41 and
                        statusCode != 43 and statusCode != 60 and statusCode != 61) :
                    alarm_dic["stop"] += 1
            elif (_type == 'v2.edgeBackSource' or _type == 'v2.edgePullStart') :
                alarm_dic["other"] += 1

        return timestamp 
    else :
        return 0
# end get_line_json 

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
        while (sendc < CONF["resend_count"]) :
            if send_http_param(param) == 200 :
                break
            else : 
                sendc += 1
                print "resend time count:%d" % sendc
        # end while 
    # end fo 
# end send_log_content 
def send_log_content_batch() :
    for k,v in watch_dic.items():
        sjson = json.dumps(v)
        
        send_log_content(sjson)    
    watch_dic.clear()
# end send_log_content_batch


def get_log_content(logoffset):
    ttstmap = logoffset['tstamp']
    tlinesc = logoffset['linesc']
    toffset = logoffset['offset']

    try :
        f = open(CONF["log_file"], 'r')
        
        # find first timestamp 
        ftstamp = 0
        while True :
            line = f.readline()
            if (line != "") :
                str_list = line.split("EDGE")
                if len(str_list) == 3:
                    json_obj = json.loads(str_list[1])
                    if json_obj.has_key('timestamp') == True :
                        ftstamp = json_obj['timestamp']
                        break
            else :
                break
        print "ftstamp:%d ttstmap:%d delta:%d" % (ftstamp, ttstmap, ttstmap-ftstamp)
        if (ftstamp > ttstmap or ftstamp == 0) :
            set_log_offset(logoffset, ftstamp, 0, 0)
            return
        
        f.seek(toffset, 0)
        tstamp = ttstmap
        try :
            lines = f.readlines()
            for line in lines :
                tlinesc += 1
                toffset += len(line)  
                ctstamp = get_line_json(line) 
                if (ctstamp > 0) :
                    tstamp = ctstamp
                
                if (len(watch_dic) == CONF["max_line_count"]) :
                    send_log_content_batch()
                    set_log_offset(logoffset, tstamp, tlinesc, toffset)
                    print "MAX tstamp:%d linesc:%d offset:%d" % (tstamp, logoffset['linesc'], logoffset['offset'])
        finally:
            send_log_content_batch()
            set_log_offset(logoffset, tstamp, tlinesc, toffset)
            print "FINALLY tstamp:%d linesc:%d offset:%d" % (tstamp, logoffset['linesc'], logoffset['offset'])
                
            f.close()
            return True
    except:
        print "Error: not found file or open file failed"
        return False
# end get_log_content


def _main_() :
    CONF_FILE = "./report_log.conf"
    if (len(sys.argv) == 1) :
        abspath = os.path.abspath(sys.argv[0])
        abspath = os.path.dirname(abspath)+"/"
        CONF_FILE = abspath+"report_log.conf"
        print CONF_FILE
    elif (len(sys.argv) == 2) :
        CONF_FILE = sys.argv[1]
        print CONF_FILE
    else :
        print "%s [*.conf]" % sys.argv[0]
        return
    get_log_conf(CONF_FILE) 
    print "##### INIT CONF END #####"
    
    logoffset = {'tstamp':0, 'linesc':0, 'offset':0}
    get_log_offset(logoffset)
    print "INIT tstamp:%d linesc:%d offset:%d" % (logoffset['tstamp'], logoffset['linesc'], logoffset['offset'])
    
    sendtime = 0;
    alarmtime = time.time();
    while True:
        if (sendtime >= int(CONF["report_poll"])) :
            print "Start time:%d" %  time.time()
            get_log_content(logoffset)
            print "End time:%d" %  time.time()
            sendtime = 0
        else :
            sendtime += SLEEP_TIME
        
        currentime = time.time()
        deltatime = (currentime-alarmtime)
        if (CONF["alarm_flag"]) :
            if ( deltatime >= int(CONF["alarm_time"]) ) :
                print "alarm stop_count:%d other_count:%d" % (alarm_dic["stop"], alarm_dic["other"])
                if ( alarm_dic["stop"] >= int(CONF["alarm_count"]) and 
                        alarm_dic["other"] == 0) :
                    set_alarm_flag(currentime, deltatime, 0)
                else :
                    set_alarm_flag(currentime, deltatime, 1)
                alarmtime = currentime
                alarm_dic["stop"] = 0
                alarm_dic["other"] = 0
        # end alarm_flag 
        
        time.sleep(SLEEP_TIME)
    # end while 
# end _main_

if __name__ == "__main__":
    _main_()
# end __main__
