package DY.HaeDollarGo_Spring.global.common;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Getter
@MappedSuperclass
public abstract class BaseEntity {

    @JsonIgnore
    @CreatedDate
    private LocalDateTime createdDate;

    @JsonIgnore
    @LastModifiedDate
    @Column(insertable = false)
    private LocalDateTime modifiedDate;
}
