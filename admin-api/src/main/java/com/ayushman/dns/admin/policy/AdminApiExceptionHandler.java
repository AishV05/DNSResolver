package com.ayushman.dns.admin.policy;

import com.ayushman.dns.admin.fleet.ResolverFleetConflictException;
import com.ayushman.dns.admin.fleet.ResolverRegistrationNotFoundException;
import com.ayushman.dns.admin.fleet.UnregisteredResolverPrincipalException;
import com.ayushman.dns.admin.security.AdminApiTokenNotFoundException;
import com.ayushman.dns.admin.security.AdminUserNotFoundException;
import com.ayushman.dns.admin.security.DuplicateAdminUsernameException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.web.bind.MethodArgumentNotValidException;

@RestControllerAdvice
public class AdminApiExceptionHandler {

    @ExceptionHandler(DnsPolicyRuleNotFoundException.class)
    ProblemDetail notFound(DnsPolicyRuleNotFoundException exception) {
        return problem(HttpStatus.NOT_FOUND, exception.getMessage());
    }

    @ExceptionHandler({
            AdminUserNotFoundException.class,
            AdminApiTokenNotFoundException.class,
            ResolverRegistrationNotFoundException.class
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

    @ExceptionHandler(ResolverFleetConflictException.class)
    ProblemDetail conflict(ResolverFleetConflictException exception) {
        return problem(HttpStatus.CONFLICT, exception.getMessage());
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    ProblemDetail conflict(DataIntegrityViolationException exception) {
        return problem(HttpStatus.CONFLICT, "request conflicts with persisted state");
    }

    @ExceptionHandler(UnregisteredResolverPrincipalException.class)
    ProblemDetail forbidden(UnregisteredResolverPrincipalException exception) {
        return problem(HttpStatus.FORBIDDEN, exception.getMessage());
    }

    @ExceptionHandler({
            HttpMessageNotReadableException.class,
            MethodArgumentNotValidException.class
    })
    ProblemDetail malformedRequest(Exception exception) {
        return problem(HttpStatus.BAD_REQUEST, "request body is invalid");
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
