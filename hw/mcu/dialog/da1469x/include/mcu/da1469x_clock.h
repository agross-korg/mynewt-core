/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef __MCU_DA1469X_CLOCK_H_
#define __MCU_DA1469X_CLOCK_H_

#include <stdint.h>
#include "mcu/da1469x_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize XTAL32M
 */
void da1469x_clock_sys_xtal32m_init(void);

/**
 * Enable XTAL32M
 */
void da1469x_clock_sys_xtal32m_enable(void);

/**
 * Switch sys_clk to XTAL32M
 *
 * Caller shall ensure that XTAL32M is already settled.
 */
void da1469x_clock_sys_xtal32m_switch(void);

/**
 * Switch sys_clk to XTAL32M
 *
 * Waits for XTAL32M to settle before switching.
 */
void da1469x_clock_sys_xtal32m_switch_safe(void);

/**
 * Disable RC32M
 */
void da1469x_clock_sys_rc32m_disable(void);

/**
 * Enable XTAL32K
 */
void da1469x_clock_lp_xtal32k_enable(void);

/**
 * Switch lp_clk to XTAL32K
 *
 * Caller shall ensure XTAL32K is already settled.
 */
void da1469x_clock_lp_xtal32k_switch(void);

/**
 * Enable RCX
 */
void da1469x_clock_lp_rcx_enable(void);

/**
 * Switch lp_clk to RCX
 *
 * Caller shall ensure RCX is already settled.
 */
void da1469x_clock_lp_rcx_switch(void);

/**
 * Calibrate RCX
 */
void da1469x_clock_lp_rcx_calibrate(void);

/**
 * Get calibrated (measured) RCX frequency
 */
uint32_t da1469x_clock_lp_rcx_freq_get(void);

/**
 * Disable RCX
 */
void da1469x_clock_lp_rcx_disable(void);

/**
 * Enable AMBA clock(s)
 *
 * @param mask
 */
static inline void
da1469x_clock_amba_enable(uint32_t mask)
{
    uint32_t primask;

    __HAL_DISABLE_INTERRUPTS(primask);
    CRG_TOP->CLK_AMBA_REG |= mask;
    __HAL_ENABLE_INTERRUPTS(primask);
}

/**
 * Disable AMBA clock(s)
 *
 * @param uint32_t mask
 */
static inline void
da1469x_clock_amba_disable(uint32_t mask)
{
    uint32_t primask;

    __HAL_DISABLE_INTERRUPTS(primask);
    CRG_TOP->CLK_AMBA_REG &= ~mask;
    __HAL_ENABLE_INTERRUPTS(primask);
}

#ifdef __cplusplus
}
#endif

#endif /* __MCU_DA1469X_CLOCK_H_ */
