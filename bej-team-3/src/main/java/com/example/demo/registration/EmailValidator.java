package com.example.demo.registration;

import org.springframework.stereotype.Service;

import java.util.function.Predicate;
import java.util.regex.Pattern;

@Service
public class EmailValidator implements Predicate<String> {
    private static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@gmail\\.com$";
    private static final Pattern PATTERN = Pattern.compile(EMAIL_REGEX);

    @Override
    public boolean test(String s) {
        if (s == null) {
            return false;
        }
        return PATTERN.matcher(s).matches();
    }
}
