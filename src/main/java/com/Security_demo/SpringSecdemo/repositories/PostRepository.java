package com.Security_demo.SpringSecdemo.repositories;

import com.Security_demo.SpringSecdemo.entities.PostEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PostRepository extends JpaRepository<PostEntity, Long> {
}
