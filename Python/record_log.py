# encoding: utf-8
import logging
from logging.handlers import RotatingFileHandler


########################################################
# Author Zimskyzeng
#
# 脚本功能
# 导入日志模块
#
########################################################

class MyLog:
    def __init__(self):
        # 配置日志文件
        self.logfile_name = "tmp.log"
        # 配置日志级别
        self.log_level = logging.DEBUG
        # 获取日志对象
        self.logger_obj = logging.RootLogger(self.log_level)

    def get_logger(self):
        """ 配置日志Handler """
        fh = RotatingFileHandler(self.logfile_name, maxBytes=10 * 1024 * 1024, backupCount=5)
        sh = logging.StreamHandler()

        fmt = logging.Formatter("%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s %(message)s")
        sh.setFormatter(fmt)
        fh.setFormatter(fmt)

        self.logger_obj.addHandler(sh)
        self.logger_obj.addHandler(fh)
        return self.logger_obj


if __name__ == '__main__':
    m = MyLog().get_logger()
    m.debug("debug")
    m.info("info")
    m.error("error")
