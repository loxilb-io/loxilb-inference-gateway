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
 * The header is read as written. A Go export cannot spell a const pointer
 * (cgo writes "uint32_t*" for a *C.uint32_t parameter), so no prototype of
 * an export in it may carry one; until WP-D the header's text was read with
 * const defined away for the three llb_ai_kv_best_worker had, which the
 * datapath has since dropped (cicd/common/ai_gw_exports_includes.sh keeps
 * the define from coming back).
 *
 * Compared: parameter count and order, the return type, and each
 * parameter's type as C sees it, qualifiers included -- a difference between
 * two spellings of one C type (C.int and int32_t) is not one. Not compared:
 * whether two parameters of the same type are passed in the right order.
 */

#ifndef __LOXINET_AI_GW_EXPORTS_H__
#define __LOXINET_AI_GW_EXPORTS_H__

#include "sockproxy_ai_gw.h"

#endif /* __LOXINET_AI_GW_EXPORTS_H__ */
