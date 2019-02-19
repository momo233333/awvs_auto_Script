#-*- coding:utf-8 -*-
import requests
import json
import ssl
from functools import reduce
import os
import hashlib
import urllib2


ssl._create_default_https_context = ssl._create_unverified_context
requests.urllib3.disable_warnings()
#---------------------------登录信息---------------------------------
with open("login.ini") as login:
    for l in login.readlines():
        if not l.find('username'):
            username = l.split(":")[1].strip()
        if not l.find('password'):
            password = l.split(":")[1].strip()
    pw = hashlib.sha256(password).hexdigest()
    ssl._create_default_https_context = ssl._create_unverified_context
    url_login = "https://localhost:3443/api/v1/me/login"
    send_headers_login = {
        'Host': 'localhost:3443',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/json;charset=utf-8'
    }
    data_login = '{"email":"' + username + '","password":"' + pw + '","remember_me":false}'
    print data_login
    response_login = requests.post(url_login, data=data_login,headers=send_headers_login,verify=False)
    print response_login
    apikey = response_login.headers['X-Auth']
    COOOOOOOOkie = response_login.headers['Set-Cookie']

awvs_url = "https://localhost:3443/"
headers = {
    'Host':'localhost:3443',
	'Accept': 'application/json, text/plain, */*',
	'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
	'Content-Type':'application/json;charset=utf-8',
	'X-Auth':apikey,
	'Cookie':COOOOOOOOkie
}
#-------------------------------添加扫描------------------------------
report_id = []
def add_scan():
    with open('awvs_scan.txt','r') as f:
        target_lists = [l.strip() for l in f.readlines()]
        for target in target_lists:
            data = {"address":target, "criticality":"10"}
            response = requests.post(awvs_url + "/api/v1/targets",data=json.dumps(data),headers=headers,timeout=30,verify=False)
            result = json.loads(response.content)
            target_id = result['target_id']
            report_id.append(target_id)
            start_scan(target_id)
            print u"添加任务："+result['address']
        print u'添加任务完成！'
#--------------------------------开始扫描任务----------------------------
def start_scan(target_id):
    scaned_url_lists = get_scan_list()
    if target_id in scaned_url_lists:
        print "repeat"
        return
    else:
        scan_data = {"target_id":target_id, "profile_id":"11111111-1111-1111-1111-111111111111","schedule": {"disable": False,"start_date":None,"time_sensitive": False},"report_template_id":"11111111-1111-1111-1111-111111111115"}
        try:
            response = requests.post(awvs_url+"/api/v1/scans",data=json.dumps(scan_data),headers=headers,timeout=30,verify=False)
        except Exception as e:
            print(str(e))
            return
#-----------------------------获取扫描列表---------------------------------
def get_scan_list():
    response = requests.get(awvs_url+"/api/v1/scans", headers=headers, timeout=30, verify=False)
    result = json.loads(response.content)
    target_url = []
    for scan_target in result['scans']:
        target_url.append(scan_target['target']['address'])
    return target_url
#-----------------------------下载扫描报告-----------------------------------
def down_report():
    response = requests.get(awvs_url+"/api/v1/reports", headers=headers, verify=False)
    result = json.loads(response.content)
    report_list = result.get('reports')
    for rep in report_list:
        pdf_down_url = awvs_url.rstrip('/')+rep['download'][1]
        target_url = rep['source']['description']
        req = requests.get(pdf_down_url, headers=headers, verify=False)
        file_name = target_url.split("://")[1].rstrip(";")
        file_name = reduce(lambda file_name, char: file_name.replace(char, "_"), "/\:;*?", file_name)
        isExists = os.path.exists("./reports")
        if not isExists:
            os.makedirs("./reports")
        with open("./reports/" + file_name + ".pdf",'wb') as report_file:
            print u'正在下载'+target_url
            report_file.write(req.content)
#--------------------------删除杀扫描目标-------------------------
def del_target():
    response = requests.get(awvs_url+"/api/v1/targets",headers=headers,timeout=30,verify=False)
    target_list = json.loads(response.content)
    target_id_list = target_list.get('targets')
    for target_id_dict in target_id_list:
        target_id = target_id_dict['target_id']
        target = target_id_dict['address']
        print u"正在删除 " + target + "..."
        del_url = awvs_url+"api/v1/targets/"+target_id
        print del_url
        del_resp = requests.delete(del_url,headers=headers,verify=False)
    print u"删除完成!"
#---------------------------删除扫描任务--------------------------------
def del_scan():
    response = requests.get(awvs_url+"/api/v1/scans",headers=headers,timeout=30,verify=False)
    scan_list = json.loads(response.content)
    scan_id_list = scan_list.get('scans')
    for scan_id_dict in scan_id_list:
        scan_id = scan_id_dict['scan_id']
        target = scan_id_dict['target']['address']
        print u"正在删除 " + target + "..."
        del_url = awvs_url+"api/v1/scans/"+scan_id
        print del_url
        del_resp = requests.delete(del_url,headers=headers,verify=False)
    print u"删除完成！"
#---------------------------删除报告-------------------------------------------
def del_report():
    response = requests.get(awvs_url+"/api/v1/reports", headers=headers, verify=False)
    result = json.loads(response.content)
    report_list = result.get('reports')
    for rep in report_list:
        pdf_down_url = awvs_url.rstrip('/')+rep['download'][1]
        target_url = rep['source']['description']
        del_id = rep['report_id']
        del_url = awvs_url+"api/v1/reports/"+del_id
        print u'正在删除'+target_url+"..."
        req = requests.delete(del_url,headers=headers,verify=False)

def main():
    print "*" * 20
    print u"\r1、使用awvs_scan.txt添加扫描任务并执行\r\n2、删除所有扫描目标（Targets）\r\n3、删除所有扫描项（Scans）\r\n4、下载所有任务报告（Reports）\r\n5、删除所有报告\r\n6、退出"
    print "*"*20
    choice = raw_input(">")
    if choice =="1":
		add_scan()
    elif  choice =="2":
		del_target()
    elif  choice =="3":
		del_scan()
    elif  choice =="4":
    	down_report()
    elif  choice =="5":
        del_report()
    elif  choice =="6":
        return
    else:
		print u"请重新运行并请输入1、2、3、4、5、6选择。"


if __name__ == "__main__":
    main()
