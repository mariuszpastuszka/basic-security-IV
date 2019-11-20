package workshop.sb.security.basics.model;

import lombok.Data;


import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.validation.constraints.NotEmpty;
import java.time.LocalDateTime;

@Entity
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotEmpty(message = "Username is required.")
    private String username;

    @NotEmpty(message = "Email is required.")
    private String email;

    private LocalDateTime created = LocalDateTime.now();

}