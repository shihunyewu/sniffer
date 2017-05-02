// =====================================================================================
//
//       Filename:settinginfo.h
//
//    Description:程序设置信息类
//
//        Version:  1.0
//        Created:
//       Revision:  none
//       Compiler:  g++
//
//         Author:  sgy
//
// =====================================================================================


#ifndef SETTINGINFO_H
#define SETTINGINFO_H

#endif // SETTINGINFO_H

#include <string>

struct SettingInfo
{
    int     iOpenDevNum;        //要打开的适配器编号
    bool    bPromiscuous;       //是否以混杂模式打开适配器
    int     iDataLimit;         //捕获数据包大小限制
    bool    bAutoBegin;         //选择适配器后自动获取
    std::string filterString;   //过滤器设置字符串，因为qt的QString转换成char数组太麻烦，所以这里用的string

    SettingInfo()
    {
        iOpenDevNum = 0;
        bPromiscuous = true;
        bAutoBegin = false;
        iDataLimit = 65535; //默认最大长度为65535，足够使用
        filterString = "ip";//默认捕获ip数据包
    }
};
