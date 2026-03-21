package com.portscanner.nuclei.matcher;

import com.portscanner.nuclei.NucleiTemplate;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.regex.Pattern;

public class RegexMatcher {

    private static final Map<String, Pattern> CACHE = new ConcurrentHashMap<>();

    public boolean matches(NucleiTemplate.Matcher matcher, String body, int statusCode) {
        if (matcher.getRegex() == null || matcher.getRegex().isEmpty()) return false;
        boolean isAnd = "and".equalsIgnoreCase(matcher.getCondition());
        for (String regex : matcher.getRegex()) {
            Pattern p = CACHE.computeIfAbsent(regex, r -> Pattern.compile(r, Pattern.DOTALL));
            boolean found = p.matcher(body).find();
            if (isAnd && !found) return matcher.isNegative();
            if (!isAnd && found) return !matcher.isNegative();
        }
        return isAnd ? !matcher.isNegative() : matcher.isNegative();
    }
}
