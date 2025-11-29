package com.komou.app.secure;

public class SecureRequestDto {
    private String data;
    private Long timestamp;

    // Getters et Setters
    public String getData() { return data; }
    public void setData(String data) { this.data = data; }

    public Long getTimestamp() { return timestamp; }
    public void setTimestamp(Long timestamp) { this.timestamp = timestamp; }
}