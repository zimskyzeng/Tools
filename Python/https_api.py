# encoding: utf-8
import hashlib
import hmac
import json
import re
import time
import sys
import urllib2
from datetime import datetime

from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.wss.v20180426 import wss_client, models as wss_model
from tencentcloud.clb.v20180317 import clb_client, models as clb_model


class BasicConfig(object):
    """ Core Config Class"""

    def __init__(self, vips):
        self.secret_id = ""
        self.secret_key = ""
        self.region = ""
        self.vips = vips

    @property
    def get_credential(self):
        return credential.Credential(self.secret_id, self.secret_key)


class SevenLevelCli(BasicConfig):
    def __init__(self, vips):
        super(SevenLevelCli, self).__init__(vips=vips)
        self.load_balance_info = {}

    def set_info_by_vips(self):
        """ Return {'lb_id': 'vip', ...} """
        try:
            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.DescribeLoadBalancersRequest()
            req.LoadBalancerVips = self.vips
            ret_str = client.DescribeLoadBalancers(req).to_json_string(indent=2)
            ret_obj = json.loads(ret_str)

            result = {}
            [result.setdefault(lb.get("LoadBalancerVips")[0], lb.get("LoadBalancerId")) for lb in ret_obj.get("LoadBalancerSet")]
            self.load_balance_info.update(result)
        except TencentCloudSDKException, error:
            print(error)
            exit(1)

    def query_listener(self, load_balance_id):
        """
        :param load_balance_id:
        :return:
            {
              "443": {
                "rules": {
                  "a.gwgo.qq.com": "loc-bb9y1k05"
                },
                "listener_id": "lbl-ansoslhl"
              }
            }
        """
        try:
            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.DescribeListenersRequest()
            req.LoadBalancerId = load_balance_id
            ret_str = client.DescribeListeners(req).to_json_string(indent=2)
            ret_obj = json.loads(ret_str)
            listeners = ret_obj.get("Listeners")

            listener_obj = {}
            for listener in listeners:
                if listener.get("Protocol") == "HTTPS":
                    vport = listener.get("Port")
                    listener_id = listener.get("ListenerId")

                    rule_obj = {}
                    rules = listener.get("Rules")
                    if len(rules) > 0:
                        for rule in rules:
                            rule_obj.setdefault(rule.get("Domain"), rule.get("LocationId"))
                    listener_obj.setdefault(str(vport), {"listener_id": listener_id, "rules": rule_obj})
            print("QueryListener Success: %s" % load_balance_id)
            print(json.dumps(listener_obj, indent=2, ensure_ascii=False))
            return listener_obj
        except TencentCloudSDKException, error:
            print("Exception Occur: QueryListener args: %s" % load_balance_id)
            print(error)
            exit(1)

    def create_listener(self, load_balance_id, vport, cert_id):
        try:
            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.CreateListenerRequest()
            req.LoadBalancerId = load_balance_id
            req.ListenerNames = ["https_" + str(vport)]
            req.Ports = [int(vport), ]
            req.Protocol = "HTTPS"
            req.Certificate = {"SSLMode": "UNIDIRECTIONAL", "CertId": cert_id}
            ret_str = client.CreateListener(req).to_json_string()
            print("CreateListener Success: CreateListener args: %s %s %s" % (load_balance_id, vport, cert_id))
            return json.loads(ret_str).get("ListenerIds")[0]
        except TencentCloudSDKException, error:
            print("Exception Occur: CreateListener args: %s %s %s" % (load_balance_id, vport, cert_id))
            print(error)
            exit(1)

    def add_rules(self, load_balance_id, listener_id, domain):
        try:
            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.CreateRuleRequest()
            req.LoadBalancerId = load_balance_id
            req.ListenerId = listener_id
            req.Rules = [{"Domain": domain, "Url": "/", "ForwardType": "HTTP", "TargetType": "NODE"}, ]
            # req.Rules = [{"Domain": domain, "Url": "/", "ForwardType": "HTTP", "TargetType": "NODE", "SessionExpireTime": 300}, ]
            ret_str = client.CreateRule(req).to_json_string()
            print("AddRule Success: AddRule args: %s %s %s" % (load_balance_id, listener_id, domain))
            return json.loads(ret_str).get("RequestId"), json.loads(ret_str).get("LocationIds")[0]
        except TencentCloudSDKException, error:
            print("Exception Occur: AddRule args: %s %s %s" % (load_balance_id, listener_id, domain))
            print(error)
            exit(1)

    def bind_host(self, load_balance_id, listener_id, rule_id, new_rs):
        try:
            re.sub(r",$", "", new_rs)
            new_rs_list = new_rs.split(",")

            client = clb_client.ClbClient(self.get_credential, self.region)
            req = clb_model.RegisterTargetsRequest()
            req.LoadBalancerId = load_balance_id
            req.ListenerId = listener_id
            req.LocationId = rule_id
            req.Targets = [{"EniIp": rs.split(":")[0], "Port": int(rs.split(":")[1])} for rs in new_rs_list]
            client.RegisterTargets(req).to_json_string(indent=2)
            print("BindHost Success: %s %s %s %s " % (load_balance_id, listener_id, rule_id, new_rs))
        except TencentCloudSDKException, error:
            print("Exception Occur: BindHost args: %s %s %s %s" % (load_balance_id, listener_id, rule_id, new_rs))
            print(error)
            exit(1)

    def check_certificate(self, certificate_id):
        try:
            client = wss_client.WssClient(self.get_credential, self.region)
            req = wss_model.DescribeCertListRequest()
            req.Id = certificate_id
            req.ModuleType = "ssl"
            return client.DescribeCertList(req)
        except TencentCloudSDKException, error:
            print(error)
            exit(1)

    def wait_request(self, request_id):
        client = clb_client.ClbClient(self.get_credential, self.region)
        req = clb_model.DescribeTaskStatusRequest()
        req.TaskId = request_id

        count = 0
        while count <= 10:
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
                print("Request %s is doing, and will retry %s times!" % (request_id, str(count)))

    def add_https(self, new_vport, cert_id, new_domain, new_rs, config_id=None):
        # Init self.vips
        self.set_info_by_vips()

        for vip in self.vips:
            # Check Seven Level Listener is exist
            load_balance_id = self.load_balance_info.get(vip)
            listener_obj = self.query_listener(load_balance_id)

            if str(new_vport) in listener_obj:
                # The listener have existed
                listener_id = listener_obj.get(str(new_vport)).get("listener_id")
                exist_domain = listener_obj.get(str(new_vport)).get("rules")

                if new_domain in exist_domain:
                    # The listener and domain have existed
                    rule_id = exist_domain.get(new_domain)

                    # Bind rs
                    self.bind_host(load_balance_id, listener_id, rule_id, new_rs)

                else:
                    # The listener have existed, but domain haven't existed
                    request_id, rule_id = self.add_rules(load_balance_id, listener_id, new_domain)

                    # Need to delay for tencent async execute
                    self.wait_request(request_id)

                    # Bind rs
                    self.bind_host(load_balance_id, listener_id, rule_id, new_rs)
            else:
                # All things is not haven.
                # Create Listener
                listener_id = self.create_listener(load_balance_id, new_vport, cert_id)

                # Create Rule
                request_id, rule_id = self.add_rules(load_balance_id, listener_id, new_domain)

                # Need to delay for tencent async execute
                self.wait_request(request_id)

                # Bind rs
                self.bind_host(load_balance_id, listener_id, rule_id, new_rs)

            # Add Location config
            if config_id is not None:
                cuc = CustomizeCli(vips=None)
                ret_obj = cuc.associate_config(load_balance_id=load_balance_id, listener_id=listener_id, domain=new_domain, location_id=rule_id, config_id=config_id)
                if "Error" in ret_obj.get("Response"):
                    print("Error Occur: Add Location config fail: %s, %s, %s, %s, %s" % (load_balance_id, listener_id, new_domain, rule_id, ret_obj.get("Response").get("Error").get("Message")))
                else:
                    print("Add Location config success: %s, %s, %s, %s" % (load_balance_id, listener_id, new_domain, rule_id))


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

    def describe_associate(self):
        api = "DescribeCustomizedConfigLBAssociateList"
        load_balance_ids = ["lb-5788rkyw", ]
        config_type = "LOCATION"
        data = {"LoadBalancerIds": load_balance_ids, "ConfigType": config_type}
        ret_obj = self._post_api(api=api, request_body=data)
        print(json.dumps(ret_obj, indent=2, ensure_ascii=False))

    def associate_config(self, load_balance_id, listener_id, domain, location_id, config_id):
        api = "AssociateCustomizedConfig"
        data = {"BindList": [{"LoadBalancerId": load_balance_id, "ListenerId": listener_id, "Domain": domain, "LocationId": location_id}, ], "UconfigId": config_id}
        ret_obj = self._post_api(api=api, request_body=data)
        return ret_obj


def convert_vips(vips):
    inp = re.sub(r",$", "", vips)
    return inp.split(",")


def help():
    print("Usage: python %s [vips] [vport] [certificate_id] [domain] [rs] [config_id:OPTIONAL]\n" % sys.argv[0])
    print("Example: python %s \"1.1.1.1,2.2.2.2\" \"8080\" \"ad24acd\" \"a.gwgo.qq.com\" \"192.168.1.1:8080,192.168.1.2:8080\" \n" % sys.argv[0])
    print("Example: python %s \"1.1.1.1,2.2.2.2\" \"8080\" \"ad24acd\" \"a.gwgo.qq.com\" \"192.168.1.1:8080,192.168.1.2:8080\" \"c12agiae\" \n" % sys.argv[0])


if __name__ == '__main__':
    args = sys.argv
    if len(args) < 5:
        help()
    else:
        vips = convert_vips(args[1])
        slc = SevenLevelCli(vips)
        slc.add_https(*args[2:])
