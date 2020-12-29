package org.sid.authservice.sec.repository;

import org.sid.authservice.sec.entities.AppRole;
import org.sid.authservice.sec.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.web.bind.annotation.CrossOrigin;
@CrossOrigin("*")
@RepositoryRestResource
public interface AppRoleRepository extends JpaRepository<AppRole, Long> {
    AppRole findByRoleName(String username);
}
