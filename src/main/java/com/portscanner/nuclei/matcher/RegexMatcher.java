package com.portscanner.nuclei.matcher;

import com.portscanner.nuclei.NucleiTemplate;

import java.util.List;
import java.util.regex.Pattern;

public class RegexMatcher {

    public boolean matches(NucleiTemplate.Matcher matcher, String body, int statusCode) {
        if (matcher.getRegex() == null || matcher.getRegex().isEmpty()) return false;
        boolean isAnd = "and".equalsIgnoreCase(matcher.getCondition());
        for (String regex : matcher.getRegex()) {
            boolean found = Pattern.compile(regex, Pattern.DOTALL).matcher(body).find();
            if (isAnd && !found) return matcher.isNegative();
            if (!isAnd && found) return !matcher.isNegative();
        }
        return isAnd ? !matcher.isNegative() : matcher.isNegative();
    }
}
