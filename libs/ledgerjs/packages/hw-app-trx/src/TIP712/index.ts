import Transport from "@ledgerhq/hw-transport";
import { hexBuffer, splitPath } from "../utils";
import type {
  TIP712Message,
  TIP712MessageTypes,
  TIP712MessageTypesEntry,
  StructImplemData,
  StructDefData,
  FilteringInfoContractName,
  FilteringInfoShowField,
  MessageFilters,
} from "./types";
import { LoadConfig } from "../services/types";
import { getLoadConfig } from "../services/loadConfig";
import {
  getFiltersForMessage,
  sortObjectAlphabetically,
  getCoinRefTokensMap,
  makeTypeEntryStructBuffer,
  getFilterDisplayNameAndSigBuffers,
  intAsHexBytes,
  getPayloadForFilterV2,
  destructTypeFromString,
  TIP712_TYPE_PROPERTIES,
  TIP712_TYPE_ENCODERS,
} from "./utils";
import { findTRC20SignaturesInfo, byContractAddressAndChainId } from "../services/ledger";

type MakeRecursiveFieldStructImplemParams = {
  transport: Transport;
  loadConfig: LoadConfig;
  chainId: number;
  erc20SignaturesBlob: string | null | undefined;
  types: TIP712MessageTypes;
  filters: MessageFilters | undefined;
  shouldUseV1Filters: boolean;
  coinRefsTokensMap: Record<number, { token: string; coinRefMemorySlot?: number }>;
};

const CLA = 0xe0;

export const signTIP712HashedMessage = (
  transport: Transport,
  path: string,
  domainSeparatorHex: string,
  hashStructMessageHex: string,
): Promise<string> => {
  const domainSeparator = hexBuffer(domainSeparatorHex);
  const hashStruct = hexBuffer(hashStructMessageHex);
  const paths = splitPath(path);
  const buffer = Buffer.alloc(1 + paths.length * 4 + 32 + 32, 0);

  let offset = 0;
  buffer[0] = paths.length;
  paths.forEach((element, index) => {
    buffer.writeUint32BE(element, 1 + 4 * index);
  });

  offset = 1 + 4 * paths.length;
  domainSeparator.copy(buffer, offset);
  offset += 32;
  hashStruct.copy(buffer, offset);

  return transport.send(CLA, 0x0c, 0x00, 0x00, buffer).then(response => {
    return response.slice(0, 65).toString("hex");
  });
};

/**
 * @ignore for the README
 *
 * This method is used to send the message definition with all its types.
 * This method should be used before the sendStructImplem one
 *
 * @param {String} structType
 * @param {String|Buffer} value
 * @returns {Promise<void>}
 */
const sendStructDef = (transport: Transport, structDef: StructDefData): Promise<Buffer> => {
  enum APDU_FIELDS {
    CLA = 0xe0,
    INS = 0x1a,
    P1_complete = 0x00,
    P1_partial = 0x01,
    P2_name = 0x00,
    P2_field = 0xff,
  }

  const { structType, value } = structDef;
  const data =
    structType === "name" && typeof value === "string"
      ? Buffer.from(value, "utf-8")
      : (value as Buffer);

  return transport.send(
    APDU_FIELDS.CLA,
    APDU_FIELDS.INS,
    APDU_FIELDS.P1_complete,
    structType === "name" ? APDU_FIELDS.P2_name : APDU_FIELDS.P2_field,
    data,
  );
};

/**
 * @ignore for the README
 *
 * This method provides a trusted new display name to use for the upcoming field.
 * This method should be used after the sendStructDef one.
 *
 * If the method describes an empty name (length of 0), the upcoming field will be taken
 * into account but won’t be shown on the device.
 *
 * The signature is computed on :
 * json key length || json key || display name length || display name
 *
 * signed by the following secp256k1 public key:
 * 0482bbf2f34f367b2e5bc21847b6566f21f0976b22d3388a9a5e446ac62d25cf725b62a2555b2dd464a4da0ab2f4d506820543af1d242470b1b1a969a27578f353
 *
 * @param {String} structType "root" | "array" | "field"
 * @param {string | number | StructFieldData} value
 * @returns {Promise<Buffer | void>}
 */
const sendStructImplem = async (
  transport: Transport,
  structImplem: StructImplemData,
): Promise<Buffer | void> => {
  enum APDU_FIELDS {
    CLA = 0xe0,
    INS = 0x1c,
    P1_complete = 0x00,
    P1_partial = 0x01,
    P2_root = 0x00,
    P2_array = 0x0f,
    P2_field = 0xff,
  }

  const { structType, value } = structImplem;

  if (structType === "root") {
    return transport.send(
      APDU_FIELDS.CLA,
      APDU_FIELDS.INS,
      APDU_FIELDS.P1_complete,
      APDU_FIELDS.P2_root,
      Buffer.from(value, "utf-8"),
    );
  }

  if (structType === "array") {
    return transport.send(
      APDU_FIELDS.CLA,
      APDU_FIELDS.INS,
      APDU_FIELDS.P1_complete,
      APDU_FIELDS.P2_array,
      Buffer.from(intAsHexBytes(value, 1), "hex"),
    );
  }

  if (structType === "field") {
    const { data: rawData, type, sizeInBits } = value;
    const encodedData: Buffer | null = TIP712_TYPE_ENCODERS[type.toUpperCase()]?.(
      rawData,
      sizeInBits,
    );

    if (encodedData) {
      // const dataLengthPer16Bits = (encodedData.length & 0xff00) >> 8;
      const dataLengthPer16Bits = Math.floor(encodedData.length / 256);
      // const dataLengthModulo16Bits = encodedData.length & 0xff;
      const dataLengthModulo16Bits = encodedData.length % 256;

      const data = Buffer.concat([
        Buffer.from(intAsHexBytes(dataLengthPer16Bits, 1), "hex"),
        Buffer.from(intAsHexBytes(dataLengthModulo16Bits, 1), "hex"),
        encodedData,
      ]);

      const bufferSlices = new Array(Math.ceil(data.length / 256))
        .fill(null)
        .map((_, i) => data.subarray(i * 255, (i + 1) * 255));

      for (const bufferSlice of bufferSlices) {
        await transport.send(
          APDU_FIELDS.CLA,
          APDU_FIELDS.INS,
          bufferSlice !== bufferSlices[bufferSlices.length - 1]
            ? APDU_FIELDS.P1_partial
            : APDU_FIELDS.P1_complete,
          APDU_FIELDS.P2_field,
          bufferSlice,
        );
      }
    }
  }

  return Promise.resolve();
};

async function sendFilteringInfo(
  transport: Transport,
  type: "activate",
  loadConfig: LoadConfig,
): Promise<Buffer>;
async function sendFilteringInfo(
  transport: Transport,
  type: "contractName",
  loadConfig: LoadConfig,
  data: FilteringInfoContractName,
): Promise<Buffer>;
async function sendFilteringInfo(
  transport: Transport,
  type: "showField",
  loadConfig: LoadConfig,
  data: FilteringInfoShowField,
): Promise<Buffer>;
async function sendFilteringInfo(
  transport: Transport,
  type: "activate" | "contractName" | "showField",
  loadConfig: LoadConfig,
  data?: FilteringInfoContractName | FilteringInfoShowField,
): Promise<Buffer | void> {
  enum APDU_FIELDS {
    CLA = 0xe0,
    INS = 0x1e,
    P1 = 0x00,
    P2_activate = 0x00,
    P2_show_field = 0xff, // for v1 of filters
    P2_message_info = 0x0f,
    P2_datetime = 0xfc,
    P2_amount_join_token = 0xfd,
    P2_amount_join_value = 0xfe,
    P2_raw = 0xff,
  }

  switch (type) {
    case "activate":
      return transport.send(
        APDU_FIELDS.CLA,
        APDU_FIELDS.INS,
        APDU_FIELDS.P1,
        APDU_FIELDS.P2_activate,
      );

    case "contractName": {
      const { displayName, filtersCount, sig } = data as FilteringInfoContractName;
      const { displayNameBuffer, sigBuffer } = getFilterDisplayNameAndSigBuffers(displayName, sig);
      const filtersCountBuffer = Buffer.from(intAsHexBytes(filtersCount, 1), "hex");

      const payload = Buffer.concat([displayNameBuffer, filtersCountBuffer, sigBuffer]);
      return transport.send(
        APDU_FIELDS.CLA,
        APDU_FIELDS.INS,
        APDU_FIELDS.P1,
        APDU_FIELDS.P2_message_info,
        payload,
      );
    }

    case "showField": {
      const {
        displayName,
        sig,
        format,
        coinRef,
        chainId,
        coinRefsTokensMap,
        shouldUseV1Filters,
        erc20SignaturesBlob,
      } = data as FilteringInfoShowField;
      const { displayNameBuffer, sigBuffer } = getFilterDisplayNameAndSigBuffers(displayName, sig);

      if (shouldUseV1Filters) {
        const payload = Buffer.concat([displayNameBuffer, sigBuffer]);
        return transport.send(
          APDU_FIELDS.CLA,
          APDU_FIELDS.INS,
          APDU_FIELDS.P1,
          APDU_FIELDS.P2_show_field,
          payload,
        );
      }

      const isTokenAddress = format === "token";
      if (isTokenAddress && coinRef !== undefined) {
        const { token, deviceTokenIndex } = coinRefsTokensMap[coinRef];
        if (deviceTokenIndex === undefined) {
          const payload = await byContractAddressAndChainId(token, chainId, erc20SignaturesBlob);
          if (payload) {
            enum PROVIDE_TOKEN_INFOS_APDU_FIELDS {
              CLA = 0xe0,
              INS = 0xca,
              P1 = 0x00,
              P2 = 0x00,
            }

            const response = await transport.send(
              PROVIDE_TOKEN_INFOS_APDU_FIELDS.CLA,
              PROVIDE_TOKEN_INFOS_APDU_FIELDS.INS,
              PROVIDE_TOKEN_INFOS_APDU_FIELDS.P1,
              PROVIDE_TOKEN_INFOS_APDU_FIELDS.P2,
              payload.data,
            );
            coinRefsTokensMap[coinRef].deviceTokenIndex = response[0];
          }
        }
      }

      // For some messages like a Permit has no token address in its message, only the amount is provided.
      // In those cases, we'll need to provide the verifying contract contained in the EIP712 domain
      // The verifying contract is refrerenced by the coinRef 255 (0xff) in CAL and in the device
      // independently of the token index returned by the app after a providerERC20TokenInfo
      const shouldUseVerifyingContract = format === "amount" && coinRef === 255;
      if (shouldUseVerifyingContract) {
        const { token } = coinRefsTokensMap[255];
        const payload = await byContractAddressAndChainId(token, chainId, erc20SignaturesBlob);

        if (payload) {
          await transport.send(0xe0, 0xca, 0x00, 0x00, payload.data);
          coinRefsTokensMap[255].deviceTokenIndex = 255;
        }
      }

      if (!format) {
        throw new Error("Missing format");
      }

      const P2FormatMap: Record<NonNullable<FilteringInfoShowField["format"]>, APDU_FIELDS> = {
        raw: APDU_FIELDS.P2_raw,
        datetime: APDU_FIELDS.P2_datetime,
        token: APDU_FIELDS.P2_amount_join_token,
        amount: APDU_FIELDS.P2_amount_join_value,
      };

      const payload = getPayloadForFilterV2(
        format,
        coinRef,
        coinRefsTokensMap,
        displayNameBuffer,
        sigBuffer,
      );
      return transport.send(
        APDU_FIELDS.CLA,
        APDU_FIELDS.INS,
        APDU_FIELDS.P1,
        P2FormatMap[format],
        payload,
      );
    }
  }
}

/**
 * @ignore for the README
 *
 * Factory to create the recursive function that will pass on each
 * field level and APDUs to describe its struct implementation
 *
 * @param {Eth["sendStructImplem"]} sendStructImplem
 * @param {EIP712MessageTypes} types
 * @returns {void}
 */
const makeRecursiveFieldStructImplem = ({
  transport,
  loadConfig,
  chainId,
  erc20SignaturesBlob,
  types,
  filters,
  shouldUseV1Filters,
  coinRefsTokensMap,
}: MakeRecursiveFieldStructImplemParams): ((
  destructedType: ReturnType<typeof destructTypeFromString>,
  data: unknown,
  path?: string,
) => Promise<void>) => {
  const typesMap = {} as Record<string, Record<string, string>>;
  for (const type in types) {
    typesMap[type] = types[type]?.reduce((acc, curr) => ({ ...acc, [curr.name]: curr.type }), {});
  }

  // This recursion will call itself to handle each level of each field
  // in order to send APDUs for each of them
  const recursiveFieldStructImplem = async (
    destructedType: ReturnType<typeof destructTypeFromString>,
    data,
    path = "",
  ) => {
    const [typeDescription, arrSizes] = destructedType;
    const [currSize, ...restSizes] = arrSizes;
    const isCustomType = !TIP712_TYPE_PROPERTIES[typeDescription?.name?.toUpperCase() || ""];

    if (Array.isArray(data) && typeof currSize !== "undefined") {
      await sendStructImplem(transport, {
        structType: "array",
        value: data.length,
      });
      for (const entry of data) {
        await recursiveFieldStructImplem([typeDescription, restSizes], entry, `${path}.[]`);
      }
    } else if (isCustomType) {
      for (const [fieldName, fieldValue] of Object.entries(data as TIP712Message["message"])) {
        const fieldType = typesMap[typeDescription?.name || ""]?.[fieldName];

        if (fieldType) {
          await recursiveFieldStructImplem(
            destructTypeFromString(fieldType),
            fieldValue,
            `${path}.${fieldName}`,
          );
        }
      }
    } else {
      const filter = filters?.fields.find(f => path === f.path);

      if (filter) {
        await sendFilteringInfo(transport, "showField", loadConfig, {
          displayName: filter.label,
          sig: filter.signature,
          format: filter.format,
          coinRef: filter.coin_ref,
          chainId,
          erc20SignaturesBlob,
          shouldUseV1Filters,
          coinRefsTokensMap,
        });
      }

      await sendStructImplem(transport, {
        structType: "field",
        value: {
          data,
          type: typeDescription?.name || "",
          sizeInBits: typeDescription?.bits,
        },
      });
    }
  };

  return recursiveFieldStructImplem;
};

/**
 * @ignore for the README
 *
 * Sign an EIP-721 formatted message following the specification here:
 * https://github.com/LedgerHQ/app-ethereum/blob/develop/doc/ethapp.asc#sign-eth-eip-712
 * @example
  eth.signEIP721Message("44'/60'/0'/0/0", {
    domain: {
      chainId: 69,
      name: "Da Domain",
      verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
      version: "1"
    },
    types: {
      "EIP712Domain": [
            { name: "name", type: "string" },
            { name: "version", type: "string" },
            { name: "chainId", type: "uint256" },
            { name: "verifyingContract", type: "address" }
        ],
      "Test": [
        { name: "contents", type: "string" }
      ]
    },
    primaryType: "Test",
    message: {contents: "Hello, Bob!"},
  })
 *
 * @param {String} path derivationPath
 * @param {Object} typedMessage message to sign
 * @param {Boolean} fullImplem use the legacy implementation
 * @returns {Promise}
 */
export const signTIP712Message = async (
  transport: Transport,
  path: string,
  typedMessage: TIP712Message,
  fullImplem = false,
  loadConfig: LoadConfig,
): Promise<string> => {
  enum APDU_FIELDS {
    CLA = 0xe0,
    INS = 0x0c,
    P1 = 0x00,
    P2_v0 = 0x00,
    P2_full = 0x01,
  }
  const { primaryType, types: unsortedTypes, domain, message } = typedMessage;
  const { calServiceURL } = getLoadConfig(loadConfig);
  // Types are sorted by alphabetical order in order to get the same schema hash no matter the JSON format
  const types = sortObjectAlphabetically(unsortedTypes) as TIP712MessageTypes;

  const shouldUseV1Filters = false;
  const filters = await getFiltersForMessage(typedMessage, shouldUseV1Filters, calServiceURL);
  const coinRefsTokensMap = getCoinRefTokensMap(filters, shouldUseV1Filters, typedMessage);

  const typeEntries = Object.entries(types) as [
    keyof TIP712MessageTypes,
    TIP712MessageTypesEntry[],
  ][];
  // Looping on all types entries and fields to send structs' definitions
  for (const [typeName, entries] of typeEntries) {
    await sendStructDef(transport, {
      structType: "name",
      value: typeName as string,
    });

    for (const { name, type } of entries) {
      const typeEntryBuffer = makeTypeEntryStructBuffer({ name, type });
      await sendStructDef(transport, {
        structType: "field",
        value: typeEntryBuffer,
      });
    }
  }

  if (filters) {
    await sendFilteringInfo(transport, "activate", loadConfig);
  }

  const erc20SignaturesBlob = !shouldUseV1Filters
    ? await findTRC20SignaturesInfo(loadConfig, domain.chainId || 0)
    : undefined;
  // Create the recursion that should pass on each entry
  // of the domain fields and primaryType fields
  const recursiveFieldStructImplem = makeRecursiveFieldStructImplem({
    transport,
    loadConfig,
    chainId: domain.chainId || 0,
    erc20SignaturesBlob,
    types,
    filters,
    shouldUseV1Filters,
    coinRefsTokensMap,
  });

  // Looping on all domain type's entries and fields to send
  // structs' implementations
  const domainName = "EIP712Domain";
  await sendStructImplem(transport, {
    structType: "root",
    value: domainName,
  });
  const domainTypeFields = types[domainName];
  for (const { name, type } of domainTypeFields) {
    const domainFieldValue = domain[name];
    await recursiveFieldStructImplem(destructTypeFromString(type as string), domainFieldValue);
  }

  if (filters) {
    const { contractName, fields } = filters;
    const contractNameInfos = {
      displayName: contractName.label,
      filtersCount: fields.length,
      sig: contractName.signature,
    };
    await sendFilteringInfo(transport, "contractName", loadConfig, contractNameInfos);
  }

  // Looping on all primaryType type's entries and fields to send
  // struct' implementations
  await sendStructImplem(transport, {
    structType: "root",
    value: primaryType,
  });
  const primaryTypeFields = types[primaryType];
  for (const { name, type } of primaryTypeFields) {
    const primaryTypeValue = message[name];
    await recursiveFieldStructImplem(
      destructTypeFromString(type as string),
      primaryTypeValue,
      name,
    );
  }

  // Sending the final signature.
  const paths = splitPath(path);
  const signatureBuffer = Buffer.alloc(1 + paths.length * 4);
  signatureBuffer[0] = paths.length;
  paths.forEach((element, index) => {
    signatureBuffer.writeUInt32BE(element, 1 + 4 * index);
  });

  return transport
    .send(
      APDU_FIELDS.CLA,
      APDU_FIELDS.INS,
      APDU_FIELDS.P1,
      fullImplem ? APDU_FIELDS.P2_v0 : APDU_FIELDS.P2_full,
      signatureBuffer,
    )
    .then(response => {
      return response.slice(0, 65).toString("hex");
    });
};
