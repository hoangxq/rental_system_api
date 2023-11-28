package com.demo.rental_system_api.web.dto.request;

import lombok.Data;

import java.util.Date;
import java.util.List;

@Data
public class CreateMonthBillRequest {
    private Date dueDate;
    private Date paymentDate;
    private String note;
    private List<UsedServiceRequest> usedServiceRequests;
    private Integer contractId;

    @Data
    public static class UsedServiceRequest {
        private Integer serviceId;
        private Integer quantity;
    }
}
