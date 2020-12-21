#!/bin/bash

# =====================================================
# 处理参数输入返回固定格式
# 
# 提取规则: 1
# 返回: 1
# echo ${INPUT} | sed -r -n '/^[0-9]+$/p'

# 提取规则: 1-10
# 返回: 1,2,3,4,5,6,7,8,9,10
# echo ${INPUT} | sed -r -n '/^[0-9]+-[0-9]+$/p'

# 提取规则: 1,2,3,4,5
# 返回: 1,2,3,4,5
# echo ${INPUT} | sed -r -n '/^[0-9]+,[0-9]+$/p'
#
# =====================================================

INPUT=$1
RET=""

# 打印输入参数
echo "Input: $INPUT"

if [ -n "$(echo ${INPUT} | sed -r -n '/^[0-9]+$/p')" ] ; then
  RET=${INPUT}

elif [ -n "$(echo ${INPUT} | sed -r -n '/^[0-9]+-[0-9]+$/p')" ] ; then
  INPUT_FROM="$( echo ${INPUT} | sed -r 's/^([0-9]+)-[0-9]+$/\1/g')"
  echo "INPUT_FROM: $INPUT_FROM"
  INPUT_END="$( echo ${INPUT} | sed -r 's/^[0-9]+-([0-9]+)$/\1/g')"
  echo "INPUT_END: $INPUT_END"  
  
  # 循环遍历生成返回值
  for ((i=${INPUT_FROM};i<=${INPUT_END};i++)) ; do
    RET+=${i},
  done  

elif [ -n "$(echo ${INPUT} | sed -r -n '/^[0-9]+(,[0-9]+)+$/p')" ] ; then
  RET=${INPUT}
fi

echo "RET: $RET"
