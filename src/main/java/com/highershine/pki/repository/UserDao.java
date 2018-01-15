package com.highershine.pki.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.highershine.pki.model.User;

public interface UserDao extends JpaRepository<User, Long> {
    
}