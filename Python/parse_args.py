#!/usr/bin/env python3
# encoding: utf-8

import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", help="Please input name", default=None)
    parser.add_argument("--age", help="Please input age", default=None)
    parser.add_argument("--addr", help="Please input addr", default=None)

    # 添加互斥参数
    # group1 = parser.add_mutually_exclusive_group()
    # group1.add_argument("-a", action="store_true")

    # 如果使用了-a，则a的值设置成const的值，即22
    parser.add_argument("-a", action="store_const", const=22)

    # 此时若带-b选项，则b的值为False。否则为True
    parser.add_argument("-b", action="store_false")

    args = parser.parse_args()

    name = args.name
    age = args.age
    addr = args.addr

    print(args)

    print("[name]: {}, [age]: {}, [addr]: {}".format(name, age, addr))


if __name__ == '__main__':
    main()
