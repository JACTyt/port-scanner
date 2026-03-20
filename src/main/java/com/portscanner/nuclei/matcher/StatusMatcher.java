package com.portscanner.nuclei.matcher;

import com.portscanner.nuclei.NucleiTemplate;

public class StatusMatcher {

    public boolean matches(NucleiTemplate.Matcher matcher, int statusCode) {
        if (matcher.getStatus() == null || matcher.getStatus().isEmpty()) return false;
        boolean result = matcher.getStatus().contains(statusCode);
        return matcher.isNegative() != result;
    }
}
