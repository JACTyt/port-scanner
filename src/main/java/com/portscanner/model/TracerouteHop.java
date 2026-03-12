package com.portscanner.model;

public record TracerouteHop(int hopNumber, String ip, String hostname, double rttMs) {}
