/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * ai_gw_exports.h -- the datapath's AI Gateway bridge header, as the Go
 * exports of this package see it.
 *
 * The C side calls the Go exports by name through the prototypes in
 * sockproxy_ai_gw.h. A Go file with //export functions has its cgo preamble
 * copied into _cgo_export.h ahead of the prototypes cgo derives from the Go
 * signatures, so a file that includes this header turns an export whose Go
 * parameter list differs from the datapath's prototype into a "conflicting
 * types" compile error in this package. Without it such an export builds and
 * links by name, and misreads its arguments at run time.
 *
 * Every file of this package that needs the bridge's types includes this
 * header, not sockproxy_ai_gw.h directly: the preambles of the exporting
 * files (dpebpf_linux.go among them) share one translation unit in
 * _cgo_export.h, and the first inclusion there of a header decides how it
 * is read for all of them.
 *
 * A Go export cannot spell a const pointer (cgo writes "uint32_t*" for a
 * *C.uint32_t parameter), and a qualifier does not change how arguments are
 * passed, so the text of sockproxy_ai_gw.h itself is read with const
 * removed (it has three, on llb_ai_kv_best_worker). Everything it includes
 * is read first, as written: dpebpf_linux.go declares
 * kv_compute_block_hashes from sockproxy_kv_exact.h with its const.
 *
 * Compared: parameter count and order, and the return type, and each
 * parameter's type as C sees it -- a difference between two spellings of one
 * C type (C.int and int32_t) is not one. Not compared: const, and whether two
 * parameters of the same type are passed in the right order.
 */

#ifndef __LOXINET_AI_GW_EXPORTS_H__
#define __LOXINET_AI_GW_EXPORTS_H__

/* Read as written, before the define below; with their guards set, the
 * #includes inside sockproxy_ai_gw.h read nothing while const is removed. */
#include <stdint.h>
#include "sockproxy_kv_exact.h"

#define const
#include "sockproxy_ai_gw.h"
#undef const

#endif /* __LOXINET_AI_GW_EXPORTS_H__ */
