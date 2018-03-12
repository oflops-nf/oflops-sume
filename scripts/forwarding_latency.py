#!/usr/bin/python3
#-*- coding: utf-8 -*-
"""
Author: Rémi Oudin.
Date: 2017-06-15
"""

from subprocess import Popen, PIPE, TimeoutExpired
import argparse
import re
import time
from os import chdir, environ
from os.path import abspath

PACKET_PATTERN = r'[0-9]+ packets '
MAX_PER_TEST = 20
MAX_ACCEPTED = 200
CONFIG_PREFIX = "sample_config/"


def set_size(size, config_file):
    """ Changes the size of sent packets.
    """
    file_handle = open(config_file, 'r')
    file_string = file_handle.read()
    file_handle.close();

    file_string = re.sub(r'pkt_size=[0-9]+', "pkt_size=%d" % size, file_string)

    file_handle = open(config_file, 'w')
    file_handle.write(file_string)
    file_handle.close

def set_query_delay(size, config_file):
    """ Changes the size of sent packets.
    """
    file_handle = open(config_file, 'r')
    file_string = file_handle.read()
    file_handle.close();

    file_string = re.sub(r'query_delay=[0-9]+', "query_delay=%d" % size, file_string)

    file_handle = open(config_file, 'w')
    file_handle.write(file_string)
    file_handle.close

def set_rate(rate, config_file):
    """ Changes the rate of sent packets.
    """
    file_handle = open(config_file, 'r')
    file_string = file_handle.read()
    file_handle.close();

    file_string = re.sub(r'data_rate=[0-9]+', "data_rate=%d" % rate, file_string)

    file_handle = open(config_file, 'w')
    file_handle.write(file_string)
    file_handle.close

def set_ipg(rate, config_file):
    """ Changes the IPG of sent packets.
    """
    file_handle = open(config_file, 'r')
    file_string = file_handle.read()
    file_handle.close();

    file_string = re.sub(r'probe_snd_interval=[0-9]+', "probe_snd_interval=%d" % rate, file_string)

    file_handle = open(config_file, 'w')
    file_handle.write(file_string)
    file_handle.close()

def parse_result(results):
    """ Parses the results of one run."""
    ret = {'captured': 0, 'dropped': 0, 'valid': 0}
    splitted = results.split('\\n')
    valuable = None
    for line in splitted:
        if line.startswith("device nf1"):
            valuable = line
    if not valuable:
        return None
    re_cap = re.compile(PACKET_PATTERN + r'captured')
    re_drop = re.compile(PACKET_PATTERN + r'dropped')
    re_valid = re.compile(r'count:[0-9]+')
    cap = re.findall(re_cap, valuable)
    drop = re.findall(re_drop, valuable)
    if not cap or not drop:
        print("Something wrong happened: No cap or drop return")
        print(cap)
        print(drop)
        return None
    cap = cap[0].split(' ')[0]
    drop = drop[0].split(' ')[0]
    if cap.isdigit():
        cap_num = int(cap)
    else:
        print("Something wrong happened: Cap is not digit --> %s" % cap)
        return None
    if drop.isdigit():
        drop_num = int(drop)
    else:
        print("Something wrong happened: Drop is not a digit --> %s" % drop)
        return None
    valid = re.findall(re_valid, results)
    if not valid or len(valid[0]) < 6:
        print("Something wrong happened: No valid output")
        print(valid)
        return None
    valid = valid[0][6:]
    if valid.isdigit():
        valid_num = int(valid)
    else:
        print("Something wrong happened: Valid is not digit")
        print(valid)
        return None
    return (valid_num, cap_num, drop_num)


def run_test(test_file, index, output, expected):
    """ Run one test."""
    cmd = ["./oflops",  "-i",  "sample_config/%s" % test_file,  "-o",  "%s/%s.%d" % ("insert_delay", output, index)]
    prog = Popen(cmd, stdout=PIPE, stderr=PIPE)
    try:
        prog.wait(timeout=100)
    except TimeoutExpired as e_tmout:
        prog.kill()
        print("Timeout expired")
        return False
    stdout, stderr = prog.communicate()
    output = str(stdout)
    error = str(stderr)
    if "ERROR" in error:
        prog = Popen(["bash", "shell_source.sh"])
        prog.wait()
        return False
    print(output)
    res = parse_result(output)
    if res:
        (valid, cap, drop) = res
        if (cap-drop) < 1000:
            return False
        #if expected - 5000 < valid < expected + 5000:
        return True
    else:
        return False

def iter_tests(test_file, output, expected):
    index = 0
    total = 0
    res = False
    while index < MAX_PER_TEST and total < MAX_ACCEPTED:
        print("Running test %d" % total)
        total += 1
        res = run_test(test_file, index, output, expected)
        if res:
            print(res)
            index += 1
        time.sleep(2)
    if total == MAX_ACCEPTED:
        return 1
    return 0

if __name__ == "__main__":
    chdir("/root/oflops-turbo/")
    base = []
    other = list(range(2600, 3100, 100))
    full = base + other
    for i in full:
        output = "insert_delay.%d.log" % i
        filename = "config-netfpga-mod-flow.cfg"
        #set_size(i, CONFIG_PREFIX + filename)
        set_rate(i, CONFIG_PREFIX + filename)
        iter_tests(filename, output, 115000)
