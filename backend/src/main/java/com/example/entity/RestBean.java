package com.example.entity;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;

public record RestBean<T>(int code, T data, String message) {
    public static <T> RestBean<T> success(T data){
        return new RestBean<>(200,data,"请求成功");
    }

    public static <T>RestBean<T> success(){
        return  success(null);
    }

    public String asJsonString(){
       return JSONObject.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }
}
