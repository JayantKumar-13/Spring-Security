package com.Security_demo.SpringSecdemo.repositories;

import com.Security_demo.SpringSecdemo.entities.Session;
import com.Security_demo.SpringSecdemo.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import javax.swing.text.html.Option;
import java.util.List;
import java.util.Optional;

public interface SessionRepository extends JpaRepository<Session, Long> {
    List<Session> findByUser(User user);

    Optional<Session> findByRefreshToken(String refreshToken);
}
