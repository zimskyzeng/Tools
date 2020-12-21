#!/usr/bin/env python
# encoding: utf-8
import hashlib
import hmac
import json
import sys
import time
import re
import traceback
import urllib2
from datetime import datetime

from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.clb.v20180317 import clb_client, models as clb_model

"""
TencentCloud CLB 四层规则操作工具
1. 添加CLB规则
2. 替换RS设备
3. 删除监听器

备注：
1. ==添加CLB规则和删除监听器== 时，如涉及香港VIP，该VIP需要单独执行另起一条命令执行；
2. 使用工具前请配置BasicConfig参数；
"""


class BasicConfig(object):
    """ Core Config Class"""

    def __init__(self, vips):
        self.secret_id = ""
        self.secret_key = ""
        self.region = ""
        self.vips = vips
        self.vpc = self.get_vpc()

    @property
    def get_credential(self):
        return credential.Credential(self.secret_id, self.secret_key)

    def get_vpc(self):
        info = {
            "ap-shanghai": "vpc-",
            "ap-nanjing": "vpc-",
            "ap-shenzhen": "vpc-",
            "ap-hongkong": "vpc-",
            "ap-tianjin": "vpc-",
        }
        return info.get(self.region, "")


class FourLevelCli(BasicConfig):
    def __init__(self, vips):
        super(FourLevelCli, self).__init__(vips=vips)
        self.load_balance_info = {}

    @staticmethod
    def convert_port(list1, list2):
        """" [1, 3, 5] + [2, 4, 6] ==> [[1, 2], [3, 4], [5, 6]] """

        ret = []
        if len(list1) == len(list2):
            [ret.append([int(list1[count]), int(list2[count])])
             for count in range(len(list1))]
        else:
            raise Exception("The Length of vport and rport is not equal!")
        return ret

    def set_info_by_vips(self):
        """ Return {'lb_id': 'vip', ...} """
        try:
            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.DescribeLoadBalancersRequest()
            req.LoadBalancerVips = self.vips
            ret_str = client.DescribeLoadBalancers(
                req).to_json_string(indent=2)
            ret_obj = json.loads(ret_str)

            if ret_obj.get("TotalCount") < len(self.vips) == 1:
                self.region = "ap-hongkong"
                self.vpc = self.get_vpc()
                client = clb_client.ClbClient(self.get_credential, self.region)
                req = clb_model.DescribeLoadBalancersRequest()
                req.LoadBalancerVips = self.vips
                ret_str = client.DescribeLoadBalancers(
                    req).to_json_string(indent=2)
                ret_obj = json.loads(ret_str)

            result = {}
            [result.setdefault(lb.get("LoadBalancerVips")[0], lb.get(
                "LoadBalancerId")) for lb in ret_obj.get("LoadBalancerSet")]
            self.load_balance_info.update(result)

        except TencentCloudSDKException:
            print(traceback.format_exc())
            exit(1)

    def query_listener(self, load_balance_id):
        try:
            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.DescribeListenersRequest()
            req.LoadBalancerId = load_balance_id
            ret_str = client.DescribeListeners(req).to_json_string(indent=2)
            ret_obj = json.loads(ret_str)
            listeners = ret_obj.get("Listeners")

            listener_obj = {}
            for listener in listeners:
                if listener.get("Protocol") in ["TCP", "UDP"]:
                    vport = listener.get("Port")
                    protocol = listener.get("Protocol")
                    listener_id = listener.get("ListenerId")
                    protocol_vport_key = protocol + str(vport)
                    listener_obj.setdefault(protocol_vport_key, listener_id)

            print("QueryListener Success: %s" % load_balance_id)
            return listener_obj
        except TencentCloudSDKException:
            print("Exception Occur: QueryListener args: %s" % load_balance_id)
            print(traceback.format_exc())
            exit(1)

    def create_listener(self, load_balance_id, protocol, vport):
        try:
            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.CreateListenerRequest()
            req.LoadBalancerId = load_balance_id
            req.Protocol = protocol
            req.Ports = [int(vport), ]
            ret_obj = json.loads(client.CreateListener(
                req).to_json_string(indent=2))
            print("CreateListener success: %s %s %s" %
                  (load_balance_id, protocol, str(vport)))
            return ret_obj.get("RequestId"), ret_obj.get("ListenerIds")[0]
        except TencentCloudSDKException:
            print(traceback.format_exc())
            print("Exception occur: CreateListener args: %s %s %s" %
                  (load_balance_id, protocol, str(vport)))

    def cust_remove_rs(self, region, load_balance_id, listener_id, old_rs, rs_port):
        try:
            self.region = region
            self.vpc = self.get_vpc()
            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.DeregisterTargetsRequest()
            req.LoadBalancerId = load_balance_id
            req.ListenerId = listener_id
            req.Targets = [{"Port": int(rs_port), "EniIp": old_rs}]
            ret_str = client.DeregisterTargets(req).to_json_string()

            request_id = json.loads(ret_str).get("RequestId")
            print("Remove request: %s" % request_id)
            self.wait_request(request_id)
            print("[Remove rs] Success! Info: %s, %s, %s, %s, %s" % (region, load_balance_id, listener_id, old_rs, rs_port))
        except TencentCloudSDKException:
            print(traceback.format_exc())
            exit(1)

    def cust_bind_rs(self, region, load_balance_id, listener_id, new_rs, rs_port):
        try:
            self.region = region
            self.vpc = self.get_vpc()
            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.RegisterTargetsRequest()
            req.LoadBalancerId = load_balance_id
            req.ListenerId = listener_id
            req.Targets = [{"Port": int(rs_port), "EniIp": new_rs}]
            ret_str = client.RegisterTargets(req).to_json_string(indent=2)

            request_id = json.loads(ret_str).get("RequestId")
            print("Bind request: %s" % request_id)
            self.wait_request(request_id)
            print("[Bind rs] Success! Info: %s, %s, %s, %s, %s" % (region, load_balance_id, listener_id, new_rs, rs_port))
        except TencentCloudSDKException:
            print(traceback.format_exc())
            exit(1)

    def bind_rs(self, load_balance_id, target_obj):
        try:
            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.BatchRegisterTargetsRequest()
            req.LoadBalancerId = load_balance_id
            req.Targets = target_obj
            client.BatchRegisterTargets(req).to_json_string(indent=2)
            print("Bindrs success !")
        except TencentCloudSDKException:
            print(traceback.format_exc())
            exit(1)

    def wait_request(self, request_id):
        client = clb_client.ClbClient(self.get_credential, self.region)
        req = clb_model.DescribeTaskStatusRequest()
        req.TaskId = request_id

        count = 0
        while count <= 30:
            time.sleep(2)
            ret_str = client.DescribeTaskStatus(req).to_json_string()
            status = json.loads(ret_str).get("Status")
            if status == 0:
                print("Request %s exec done" % request_id)
                break
            elif status == 1:
                print("Request %s occur error, please check! ")
                break
            elif status == 2:
                count += 1
                print("Request %s is doing, and will retry %s times!" %
                      (request_id, str(count)))

    def add_rs(self, protocol, vport_list, rs, rport_list):
        # 将VIP转换成ID
        self.set_info_by_vips()
        vport_list = convert_para(vport_list)
        rport_list = convert_para(rport_list)
        port_obj = self.convert_port(vport_list, rport_list)

        # 根据LBID查询使用情况
        for vip in self.vips:
            # Check Four Level Listener is exist
            load_balance_id = self.load_balance_info.get(vip)
            listener_obj = self.query_listener(load_balance_id=load_balance_id)

            target_group = []
            for vport, rport in port_obj:
                new_protocol_vport = protocol + str(vport)

                if new_protocol_vport in listener_obj:
                    # The listener have existed, bind rs
                    target_group.append(
                        {"ListenerId": listener_obj[new_protocol_vport], "EniIp": rs, "Port": rport})

                else:
                    # The listener not existed, create listener
                    request_id, listener_id = self.create_listener(
                        load_balance_id=load_balance_id, protocol=protocol, vport=vport)
                    self.wait_request(request_id=request_id)

                    target_group.append(
                        {"ListenerId": listener_id, "EniIp": rs, "Port": rport})

            # bind rs
            self.bind_rs(load_balance_id=load_balance_id, target_obj=target_group)

    def _delete_listener_exec(self, load_balance_id, listener_id):
        try:
            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.DeleteListenerRequest()
            req.LoadBalancerId = load_balance_id
            req.ListenerId = listener_id
            ret_str = client.DeleteListener(req).to_json_string(indent=2)

            request_id = json.loads(ret_str).get("RequestId")
            print("Delete Listener Request: %s " % request_id)
            self.wait_request(request_id)
            print("[Delete Listener] Success! info: %s, %s" % (load_balance_id, listener_id))
        except TencentCloudSDKException:
            print(traceback.format_exc())
            exit(1)

    def delete_listener(self, protocol, vport_list):
        self.set_info_by_vips()
        vport_list = convert_para(vport_list)

        for vip in self.vips:
            # Check Four Level Listener
            load_balance_id = self.load_balance_info.get(vip)
            listener_obj = self.query_listener(load_balance_id=load_balance_id)
            for vport in vport_list:
                delete_protocol_vport = protocol + str(vport)
                if delete_protocol_vport in listener_obj:
                    self._delete_listener_exec(load_balance_id, listener_obj.get(delete_protocol_vport))

    def instead_rs(self, old_rs, new_rs):
        cci = CustomizeCli("")
        old_rs_infos = cci.query_rs(old_rs)
        print("Old Rs info: %s " % json.dumps(old_rs_infos, indent=2, ensure_ascii=False))

        if old_rs_infos is not None:
            for item in old_rs_infos:
                self.cust_bind_rs(
                    region=item.get("region"),
                    load_balance_id=item.get("load_balance_id"),
                    listener_id=item.get("listener_id"),
                    new_rs=new_rs,
                    rs_port=item.get("rs_port")
                )
                self.cust_remove_rs(
                    region=item.get("region"),
                    load_balance_id=item.get("load_balance_id"),
                    listener_id=item.get("listener_id"),
                    old_rs=old_rs,
                    rs_port=item.get("rs_port")
                )

    def delete_rs(self, rs):
        cci = CustomizeCli("")
        delete_rs_infos = cci.query_rs(rs)
        print("Delete Rs info: %s " % json.dumps(delete_rs_infos, indent=2, ensure_ascii=False))
        if delete_rs_infos is not None:
            for item in delete_rs_infos:
                self.cust_remove_rs(
                    region=item.get("region"),
                    load_balance_id=item.get("load_balance_id"),
                    listener_id=item.get("listener_id"),
                    old_rs=rs,
                    rs_port=item.get("rs_port")
                )

    def query_rs(self, rs):
        cci = CustomizeCli("")
        rs_infos = cci.query_rs(rs)
        print("Old Rs info: %s " % json.dumps(rs_infos, indent=2, ensure_ascii=False))


class CustomizeCli(BasicConfig):
    def __init__(self, vips):
        super(CustomizeCli, self).__init__(vips=vips)

        self.service = "clb"
        self.host = "clb.tencentcloudapi.com"
        self.endpoint = "https://" + self.host
        self.version = "2018-03-17"
        self.algorithm = "TC3-HMAC-SHA256"
        self.timestamp = int(time.time())
        self.date = datetime.utcfromtimestamp(self.timestamp).strftime("%Y-%m-%d")
        self.signed_headers = "content-type;host"

    def _splice_request(self, params):
        """
        步骤 1：拼接规范请求串
        :param params:
        :return:
        """
        http_request_method = "POST"
        canonical_uri = "/"
        canonical_querystring = ""
        ct = "application/json; charset=utf-8"
        payload = json.dumps(params)
        canonical_headers = "content-type:%s\nhost:%s\n" % (ct, self.host)
        hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        canonical_request = (http_request_method + "\n" +
                             canonical_uri + "\n" +
                             canonical_querystring + "\n" +
                             canonical_headers + "\n" +
                             self.signed_headers + "\n" +
                             hashed_request_payload)
        return canonical_request

    def _splice_signature(self, params):
        """
        步骤 2：拼接待签名字符串
        :param params:
        :return:
        """
        canonical_request = self._splice_request(params)
        credential_scope = self.date + "/" + self.service + "/" + "tc3_request"
        hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        string_to_sign = (self.algorithm + "\n" +
                          str(self.timestamp) + "\n" +
                          credential_scope + "\n" +
                          hashed_canonical_request)
        return credential_scope, string_to_sign

    @staticmethod
    def sign(key, msg):
        """
        步骤 3：计算签名
        :param key:
        :param msg:
        :return:
        """
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def _calc_signature(self, params):
        """
        步骤 4：拼接 Authorization
        :param params:
        :return:
        """
        credential_scope, string_to_sign = self._splice_signature(params)
        secret_id, secret_key = self.secret_id, self.secret_key
        secret_date = self.sign(("TC3" + secret_key).encode("utf-8"), self.date)
        secret_service = self.sign(secret_date, self.service)
        secret_signing = self.sign(secret_service, "tc3_request")
        signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        authorization = (self.algorithm + " " +
                         "Credential=" + secret_id + "/" + credential_scope + ", " +
                         "SignedHeaders=" + self.signed_headers + ", " +
                         "Signature=" + signature)
        return authorization

    def _post_api(self, api, request_body, region=None):
        """
        步骤 5：发送post请求
        :param api:
        :param request_body:
        :return:
        """
        if region is not None:
            xregion = region
        else:
            xregion = self.region

        authorization = self._calc_signature(request_body)
        header = {"Authorization": " " + authorization, "Content-Type": " " + "application/json; charset=utf-8",
                  "Host": " " + self.host, "X-TC-Action": " " + api, "X-TC-Timestamp": " " + str(self.timestamp),
                  "X-TC-Version": " " + self.version, "X-TC-Region": " " + xregion}

        # 使用json.dumps将data转换成字符串
        data = json.dumps(request_body, ensure_ascii=False)

        request = urllib2.Request(self.endpoint, data=data, headers=header)
        response = urllib2.urlopen(request)
        obj = json.loads(response.read())
        return obj

    def query_rs(self, old_rs):
        api = "DescribeLBListeners"
        data = {"Backends": [{"VpcId": self.vpc, "PrivateIp": old_rs}]}
        ret_obj = self._post_api(api=api, request_body=data)

        result = []
        load_balace_list = ret_obj.get("Response").get("LoadBalancers")
        if len(load_balace_list) == 0:
            return None
        else:
            for load_balance in load_balace_list:
                for listener in load_balance.get("Listeners"):
                    if listener.get("Protocol") in ["TCP", "UDP"]:
                        for target in listener.get("Targets"):
                            result.append({
                                "load_balance_id": load_balance.get("LoadBalancerId"),
                                "listener_id": listener.get("ListenerId"),
                                "vport": listener.get("Port"),
                                "rs_port": target.get("Port"),
                                "region": load_balance.get("Region"),
                                "protocol": listener.get("Protocol"),
                            })
            return result


def convert_para(inp):
    inp = inp.strip()
    if "-" in inp:
        start, end = inp.split("-")
        return [i for i in range(int(start), int(end) + 1)]
    else:
        inp = re.sub(r",$", "", inp)
        return inp.split(",")


def help():
    print("Usage: python %s add_rs vip_list protocol vport_list rs rsport_list\n" % sys.argv[0])
    print("       python %s instead_rs \"_\" \"old_rs\" \"new_rs\" \n" % sys.argv[0])
    print("       python %s delete_rs \"_\" \"_rs\" \n" % sys.argv[0])
    print("       python %s delete_listener vip_list protocol vport_list \n" % sys.argv[0])
    print("       python %s query_rs \"_\" rs_ip \n" % sys.argv[0])


if __name__ == "__main__":
    args = sys.argv
    if len(args) < 3:
        help()
        exit(1)

    flc = FourLevelCli(convert_para(args[2]))
    if hasattr(flc, args[1]):
        getattr(flc, args[1])(*args[3:])
    else:
        help()
        exit(1)
