#ifndef DONGLE_ATTESTATION_PROTOCOL_H
#define DONGLE_ATTESTATION_PROTOCOL_H

/*
 * UEFI adapter ABI for Dongle's pre-OS stage.
 *
 * Install a Secure-Boot-signed vendor UEFI driver that installs this protocol
 * before dongle-uefi-stage. The GUID must remain identical to the Rust stage.
 * The adapter must not export private keys or token PINs.
 */

#include <Uefi.h>

#define DONGLE_ATTESTATION_PROTOCOL_GUID \
  { 0x8bc0c4a2, 0x12d2, 0x4e8c, \
    { 0xa5, 0x1a, 0x6d, 0x6a, 0x9c, 0x2e, 0x10, 0x01 } }

#define DONGLE_ATTESTATION_PROTOCOL_REVISION 1
#define DONGLE_MAX_SIGNATURE_SIZE 512
#define DONGLE_MAX_QUOTE_SIZE 4096
#define DONGLE_MAX_PCR_DATA_SIZE 4096

typedef struct {
  UINT8 DongleSignature[DONGLE_MAX_SIGNATURE_SIZE];
  UINTN DongleSignatureLength;
  UINT8 QuoteMessage[DONGLE_MAX_QUOTE_SIZE];
  UINTN QuoteMessageLength;
  UINT8 QuoteSignature[DONGLE_MAX_SIGNATURE_SIZE];
  UINTN QuoteSignatureLength;
  UINT8 PcrValues[DONGLE_MAX_PCR_DATA_SIZE];
  UINTN PcrValuesLength;
} DONGLE_ATTESTATION_EVIDENCE;

typedef struct _DONGLE_ATTESTATION_PROTOCOL
  DONGLE_ATTESTATION_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *DONGLE_ATTEST)(
  IN DONGLE_ATTESTATION_PROTOCOL *This,
  IN CONST UINT8 *Nonce,
  IN UINTN NonceLength,
  IN CONST UINT8 *SigningTranscript,
  IN UINTN SigningTranscriptLength,
  OUT DONGLE_ATTESTATION_EVIDENCE *Evidence
  );

struct _DONGLE_ATTESTATION_PROTOCOL {
  UINT32 Revision;
  DONGLE_ATTEST Attest;
};

extern EFI_GUID gDongleAttestationProtocolGuid;

#endif
