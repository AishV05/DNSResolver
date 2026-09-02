package com.ayushman.dns.admin.policy;

import com.ayushman.dns.admin.security.AdminApiTokenNotFoundException;
import com.ayushman.dns.admin.security.AdminUserNotFoundException;
import com.ayushman.dns.admin.security.DuplicateAdminUsernameException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class AdminApiExceptionHandler {

    @ExceptionHandler(DnsPolicyRuleNotFoundException.class)
    ProblemDetail notFound(DnsPolicyRuleNotFoundException exception) {
        return problem(HttpStatus.NOT_FOUND, exception.getMessage());
    }

    @ExceptionHandler({
            AdminUserNotFoundException.class,
            AdminApiTokenNotFoundException.class
    })
    ProblemDetail notFound(RuntimeException exception) {
        return problem(HttpStatus.NOT_FOUND, exception.getMessage());
    }

    @ExceptionHandler(DuplicateDnsPolicyRuleException.class)
    ProblemDetail conflict(DuplicateDnsPolicyRuleException exception) {
        return problem(HttpStatus.CONFLICT, exception.getMessage());
    }

    @ExceptionHandler(DuplicateAdminUsernameException.class)
    ProblemDetail conflict(DuplicateAdminUsernameException exception) {
        return problem(HttpStatus.CONFLICT, exception.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail invalidRequest(IllegalArgumentException exception) {
        return problem(HttpStatus.BAD_REQUEST, exception.getMessage());
    }

    private ProblemDetail problem(HttpStatus status, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(status.getReasonPhrase());
        return problem;
    }
}
