package com.portscanner.nuclei.matcher;

import com.portscanner.nuclei.NucleiTemplate;

public class WordMatcher {

    public boolean matches(NucleiTemplate.Matcher matcher, String body) {
        if (matcher.getWords() == null || matcher.getWords().isEmpty()) return false;
        boolean isAnd = "and".equalsIgnoreCase(matcher.getCondition());
        for (String word : matcher.getWords()) {
            boolean found = body.contains(word);
            if (isAnd && !found) return matcher.isNegative();
            if (!isAnd && found) return !matcher.isNegative();
        }
        return isAnd ? !matcher.isNegative() : matcher.isNegative();
    }
}
