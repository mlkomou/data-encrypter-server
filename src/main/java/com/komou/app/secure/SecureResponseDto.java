package com.komou.app.secure;

public class SecureResponseDto {
    private String data;
    private Long timestamp;

    // Constructeurs
    public SecureResponseDto() {}

    public SecureResponseDto(String data, Long timestamp) {
        this.data = data;
        this.timestamp = timestamp;
    }

    // Getters et Setters
    public String getData() { return data; }
    public void setData(String data) { this.data = data; }

    public Long getTimestamp() { return timestamp; }
    public void setTimestamp(Long timestamp) { this.timestamp = timestamp; }
}