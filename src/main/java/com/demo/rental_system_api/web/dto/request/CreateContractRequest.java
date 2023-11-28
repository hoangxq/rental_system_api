package com.demo.rental_system_api.web.dto.request;

import lombok.Data;

import javax.validation.constraints.NotNull;
import java.util.Date;

@Data
public class CreateContractRequest {
    private String note;
    @NotNull
    private Date startDate;
    @NotNull
    private Date dueDate;
    @NotNull
    private Float roomDeposit;

    @NotNull
    private Integer clientId;
    @NotNull
    private Integer roomId;
}
