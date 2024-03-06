// Copyright (c) HashiCorp, Inc.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        (unknown)
// source: controller/servers/services/v1/upstream_message_service.proto

package services

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// defines the set of unknown message types
type MsgType int32

const (
	MsgType_MSG_TYPE_UNSPECIFIED                MsgType = 0
	MsgType_MSG_TYPE_ECHO                       MsgType = 1 // currently this only used for testing.
	MsgType_MSG_TYPE_UNWRAP_KEYS                MsgType = 2
	MsgType_MSG_TYPE_VERIFY_SIGNATURE           MsgType = 3
	MsgType_MSG_TYPE_CLOSE_SESSION_RECORDING    MsgType = 4
	MsgType_MSG_TYPE_CLOSE_CONNECTION_RECORDING MsgType = 5
	MsgType_MSG_TYPE_CREATE_CHANNEL_RECORDING   MsgType = 6
)

// Enum value maps for MsgType.
var (
	MsgType_name = map[int32]string{
		0: "MSG_TYPE_UNSPECIFIED",
		1: "MSG_TYPE_ECHO",
		2: "MSG_TYPE_UNWRAP_KEYS",
		3: "MSG_TYPE_VERIFY_SIGNATURE",
		4: "MSG_TYPE_CLOSE_SESSION_RECORDING",
		5: "MSG_TYPE_CLOSE_CONNECTION_RECORDING",
		6: "MSG_TYPE_CREATE_CHANNEL_RECORDING",
	}
	MsgType_value = map[string]int32{
		"MSG_TYPE_UNSPECIFIED":                0,
		"MSG_TYPE_ECHO":                       1,
		"MSG_TYPE_UNWRAP_KEYS":                2,
		"MSG_TYPE_VERIFY_SIGNATURE":           3,
		"MSG_TYPE_CLOSE_SESSION_RECORDING":    4,
		"MSG_TYPE_CLOSE_CONNECTION_RECORDING": 5,
		"MSG_TYPE_CREATE_CHANNEL_RECORDING":   6,
	}
)

func (x MsgType) Enum() *MsgType {
	p := new(MsgType)
	*p = x
	return p
}

func (x MsgType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MsgType) Descriptor() protoreflect.EnumDescriptor {
	return file_controller_servers_services_v1_upstream_message_service_proto_enumTypes[0].Descriptor()
}

func (MsgType) Type() protoreflect.EnumType {
	return &file_controller_servers_services_v1_upstream_message_service_proto_enumTypes[0]
}

func (x MsgType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MsgType.Descriptor instead.
func (MsgType) EnumDescriptor() ([]byte, []int) {
	return file_controller_servers_services_v1_upstream_message_service_proto_rawDescGZIP(), []int{0}
}

type UpstreamMessageRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// the node credentials key id for the worker originated the request
	OriginatingWorkerKeyId string `protobuf:"bytes,10,opt,name=originating_worker_key_id,json=originatingWorkerKeyId,proto3" json:"originating_worker_key_id,omitempty" class:"public"` // @gotags: `class:"public"
	// the type of the encrypted_message which must have a
	// RegisterUpstreamMessageHandler or codesUnimplemented will be returned
	MsgType MsgType `protobuf:"varint,20,opt,name=msg_type,json=msgType,proto3,enum=controller.servers.services.v1.MsgType" json:"msg_type,omitempty"`
	// message will either be encrypted (ct) or plaintext (pt) based on its
	// msg_type
	//
	// Types that are assignable to Message:
	//
	//	*UpstreamMessageRequest_Ct
	//	*UpstreamMessageRequest_Pt
	Message isUpstreamMessageRequest_Message `protobuf_oneof:"message"`
}

func (x *UpstreamMessageRequest) Reset() {
	*x = UpstreamMessageRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpstreamMessageRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpstreamMessageRequest) ProtoMessage() {}

func (x *UpstreamMessageRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpstreamMessageRequest.ProtoReflect.Descriptor instead.
func (*UpstreamMessageRequest) Descriptor() ([]byte, []int) {
	return file_controller_servers_services_v1_upstream_message_service_proto_rawDescGZIP(), []int{0}
}

func (x *UpstreamMessageRequest) GetOriginatingWorkerKeyId() string {
	if x != nil {
		return x.OriginatingWorkerKeyId
	}
	return ""
}

func (x *UpstreamMessageRequest) GetMsgType() MsgType {
	if x != nil {
		return x.MsgType
	}
	return MsgType_MSG_TYPE_UNSPECIFIED
}

func (m *UpstreamMessageRequest) GetMessage() isUpstreamMessageRequest_Message {
	if m != nil {
		return m.Message
	}
	return nil
}

func (x *UpstreamMessageRequest) GetCt() []byte {
	if x, ok := x.GetMessage().(*UpstreamMessageRequest_Ct); ok {
		return x.Ct
	}
	return nil
}

func (x *UpstreamMessageRequest) GetPt() []byte {
	if x, ok := x.GetMessage().(*UpstreamMessageRequest_Pt); ok {
		return x.Pt
	}
	return nil
}

type isUpstreamMessageRequest_Message interface {
	isUpstreamMessageRequest_Message()
}

type UpstreamMessageRequest_Ct struct {
	// the encrypted upstream message. This message is encrypted with the
	// originating worker's types.NodeCredentials.
	Ct []byte `protobuf:"bytes,30,opt,name=ct,proto3,oneof" class:"secret"` // @gotags: `class:"secret"
}

type UpstreamMessageRequest_Pt struct {
	// the plaintext upstream message.
	Pt []byte `protobuf:"bytes,40,opt,name=pt,proto3,oneof" class:"public"` // @gotags: `class:"public"
}

func (*UpstreamMessageRequest_Ct) isUpstreamMessageRequest_Message() {}

func (*UpstreamMessageRequest_Pt) isUpstreamMessageRequest_Message() {}

type UpstreamMessageResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// the encryped response message. This message is encrypted with the
	// originating worker's types.NodeCredentials.
	// message will either be encrypted (ct) or plaintext (pt) based on its
	// msg_type
	//
	// Types that are assignable to Message:
	//
	//	*UpstreamMessageResponse_Ct
	//	*UpstreamMessageResponse_Pt
	Message isUpstreamMessageResponse_Message `protobuf_oneof:"message"`
}

func (x *UpstreamMessageResponse) Reset() {
	*x = UpstreamMessageResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpstreamMessageResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpstreamMessageResponse) ProtoMessage() {}

func (x *UpstreamMessageResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpstreamMessageResponse.ProtoReflect.Descriptor instead.
func (*UpstreamMessageResponse) Descriptor() ([]byte, []int) {
	return file_controller_servers_services_v1_upstream_message_service_proto_rawDescGZIP(), []int{1}
}

func (m *UpstreamMessageResponse) GetMessage() isUpstreamMessageResponse_Message {
	if m != nil {
		return m.Message
	}
	return nil
}

func (x *UpstreamMessageResponse) GetCt() []byte {
	if x, ok := x.GetMessage().(*UpstreamMessageResponse_Ct); ok {
		return x.Ct
	}
	return nil
}

func (x *UpstreamMessageResponse) GetPt() []byte {
	if x, ok := x.GetMessage().(*UpstreamMessageResponse_Pt); ok {
		return x.Pt
	}
	return nil
}

type isUpstreamMessageResponse_Message interface {
	isUpstreamMessageResponse_Message()
}

type UpstreamMessageResponse_Ct struct {
	// the encrypted upstream message. This message is encrypted with the
	// originating worker's types.NodeCredentials.
	Ct []byte `protobuf:"bytes,10,opt,name=ct,proto3,oneof" class:"secret"` // @gotags: `class:"secret"
}

type UpstreamMessageResponse_Pt struct {
	// the plaintext upstream message.
	Pt []byte `protobuf:"bytes,20,opt,name=pt,proto3,oneof" class:"public"` // @gotags: `class:"public"
}

func (*UpstreamMessageResponse_Ct) isUpstreamMessageResponse_Message() {}

func (*UpstreamMessageResponse_Pt) isUpstreamMessageResponse_Message() {}

type EchoUpstreamMessageRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Msg string `protobuf:"bytes,10,opt,name=msg,proto3" json:"msg,omitempty" class:"secret"` // @gotags: `class:"secret"
}

func (x *EchoUpstreamMessageRequest) Reset() {
	*x = EchoUpstreamMessageRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EchoUpstreamMessageRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EchoUpstreamMessageRequest) ProtoMessage() {}

func (x *EchoUpstreamMessageRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EchoUpstreamMessageRequest.ProtoReflect.Descriptor instead.
func (*EchoUpstreamMessageRequest) Descriptor() ([]byte, []int) {
	return file_controller_servers_services_v1_upstream_message_service_proto_rawDescGZIP(), []int{2}
}

func (x *EchoUpstreamMessageRequest) GetMsg() string {
	if x != nil {
		return x.Msg
	}
	return ""
}

type EchoUpstreamMessageResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Msg string `protobuf:"bytes,10,opt,name=msg,proto3" json:"msg,omitempty" class:"secret"` // @gotags: `class:"secret"
}

func (x *EchoUpstreamMessageResponse) Reset() {
	*x = EchoUpstreamMessageResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EchoUpstreamMessageResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EchoUpstreamMessageResponse) ProtoMessage() {}

func (x *EchoUpstreamMessageResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EchoUpstreamMessageResponse.ProtoReflect.Descriptor instead.
func (*EchoUpstreamMessageResponse) Descriptor() ([]byte, []int) {
	return file_controller_servers_services_v1_upstream_message_service_proto_rawDescGZIP(), []int{3}
}

func (x *EchoUpstreamMessageResponse) GetMsg() string {
	if x != nil {
		return x.Msg
	}
	return ""
}

var File_controller_servers_services_v1_upstream_message_service_proto protoreflect.FileDescriptor

var file_controller_servers_services_v1_upstream_message_service_proto_rawDesc = []byte{
	0x0a, 0x3d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x73, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x76, 0x31,
	0x2f, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x1e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x73, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x22,
	0xc6, 0x01, 0x0a, 0x16, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x39, 0x0a, 0x19, 0x6f, 0x72,
	0x69, 0x67, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6e, 0x67, 0x5f, 0x77, 0x6f, 0x72, 0x6b, 0x65, 0x72,
	0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x16, 0x6f,
	0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6e, 0x67, 0x57, 0x6f, 0x72, 0x6b, 0x65, 0x72,
	0x4b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x42, 0x0a, 0x08, 0x6d, 0x73, 0x67, 0x5f, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x14, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x27, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67, 0x54, 0x79, 0x70, 0x65,
	0x52, 0x07, 0x6d, 0x73, 0x67, 0x54, 0x79, 0x70, 0x65, 0x12, 0x10, 0x0a, 0x02, 0x63, 0x74, 0x18,
	0x1e, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x02, 0x63, 0x74, 0x12, 0x10, 0x0a, 0x02, 0x70,
	0x74, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x02, 0x70, 0x74, 0x42, 0x09, 0x0a,
	0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x48, 0x0a, 0x17, 0x55, 0x70, 0x73, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x10, 0x0a, 0x02, 0x63, 0x74, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0c, 0x48,
	0x00, 0x52, 0x02, 0x63, 0x74, 0x12, 0x10, 0x0a, 0x02, 0x70, 0x74, 0x18, 0x14, 0x20, 0x01, 0x28,
	0x0c, 0x48, 0x00, 0x52, 0x02, 0x70, 0x74, 0x42, 0x09, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x22, 0x2e, 0x0a, 0x1a, 0x45, 0x63, 0x68, 0x6f, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65,
	0x61, 0x6d, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x10, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6d,
	0x73, 0x67, 0x22, 0x2f, 0x0a, 0x1b, 0x45, 0x63, 0x68, 0x6f, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65,
	0x61, 0x6d, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x6d, 0x73, 0x67, 0x2a, 0xe5, 0x01, 0x0a, 0x07, 0x4d, 0x73, 0x67, 0x54, 0x79, 0x70, 0x65, 0x12,
	0x18, 0x0a, 0x14, 0x4d, 0x53, 0x47, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50,
	0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x11, 0x0a, 0x0d, 0x4d, 0x53, 0x47,
	0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x45, 0x43, 0x48, 0x4f, 0x10, 0x01, 0x12, 0x18, 0x0a, 0x14,
	0x4d, 0x53, 0x47, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x57, 0x52, 0x41, 0x50, 0x5f,
	0x4b, 0x45, 0x59, 0x53, 0x10, 0x02, 0x12, 0x1d, 0x0a, 0x19, 0x4d, 0x53, 0x47, 0x5f, 0x54, 0x59,
	0x50, 0x45, 0x5f, 0x56, 0x45, 0x52, 0x49, 0x46, 0x59, 0x5f, 0x53, 0x49, 0x47, 0x4e, 0x41, 0x54,
	0x55, 0x52, 0x45, 0x10, 0x03, 0x12, 0x24, 0x0a, 0x20, 0x4d, 0x53, 0x47, 0x5f, 0x54, 0x59, 0x50,
	0x45, 0x5f, 0x43, 0x4c, 0x4f, 0x53, 0x45, 0x5f, 0x53, 0x45, 0x53, 0x53, 0x49, 0x4f, 0x4e, 0x5f,
	0x52, 0x45, 0x43, 0x4f, 0x52, 0x44, 0x49, 0x4e, 0x47, 0x10, 0x04, 0x12, 0x27, 0x0a, 0x23, 0x4d,
	0x53, 0x47, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x43, 0x4c, 0x4f, 0x53, 0x45, 0x5f, 0x43, 0x4f,
	0x4e, 0x4e, 0x45, 0x43, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x52, 0x45, 0x43, 0x4f, 0x52, 0x44, 0x49,
	0x4e, 0x47, 0x10, 0x05, 0x12, 0x25, 0x0a, 0x21, 0x4d, 0x53, 0x47, 0x5f, 0x54, 0x59, 0x50, 0x45,
	0x5f, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x5f, 0x43, 0x48, 0x41, 0x4e, 0x4e, 0x45, 0x4c, 0x5f,
	0x52, 0x45, 0x43, 0x4f, 0x52, 0x44, 0x49, 0x4e, 0x47, 0x10, 0x06, 0x32, 0x9f, 0x01, 0x0a, 0x16,
	0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x84, 0x01, 0x0a, 0x0f, 0x55, 0x70, 0x73, 0x74, 0x72,
	0x65, 0x61, 0x6d, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x36, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x73, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x37, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x51, 0x5a,
	0x4f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68,
	0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x2f, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x3b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_servers_services_v1_upstream_message_service_proto_rawDescOnce sync.Once
	file_controller_servers_services_v1_upstream_message_service_proto_rawDescData = file_controller_servers_services_v1_upstream_message_service_proto_rawDesc
)

func file_controller_servers_services_v1_upstream_message_service_proto_rawDescGZIP() []byte {
	file_controller_servers_services_v1_upstream_message_service_proto_rawDescOnce.Do(func() {
		file_controller_servers_services_v1_upstream_message_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_servers_services_v1_upstream_message_service_proto_rawDescData)
	})
	return file_controller_servers_services_v1_upstream_message_service_proto_rawDescData
}

var file_controller_servers_services_v1_upstream_message_service_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_controller_servers_services_v1_upstream_message_service_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_controller_servers_services_v1_upstream_message_service_proto_goTypes = []interface{}{
	(MsgType)(0),                        // 0: controller.servers.services.v1.MsgType
	(*UpstreamMessageRequest)(nil),      // 1: controller.servers.services.v1.UpstreamMessageRequest
	(*UpstreamMessageResponse)(nil),     // 2: controller.servers.services.v1.UpstreamMessageResponse
	(*EchoUpstreamMessageRequest)(nil),  // 3: controller.servers.services.v1.EchoUpstreamMessageRequest
	(*EchoUpstreamMessageResponse)(nil), // 4: controller.servers.services.v1.EchoUpstreamMessageResponse
}
var file_controller_servers_services_v1_upstream_message_service_proto_depIdxs = []int32{
	0, // 0: controller.servers.services.v1.UpstreamMessageRequest.msg_type:type_name -> controller.servers.services.v1.MsgType
	1, // 1: controller.servers.services.v1.UpstreamMessageService.UpstreamMessage:input_type -> controller.servers.services.v1.UpstreamMessageRequest
	2, // 2: controller.servers.services.v1.UpstreamMessageService.UpstreamMessage:output_type -> controller.servers.services.v1.UpstreamMessageResponse
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_controller_servers_services_v1_upstream_message_service_proto_init() }
func file_controller_servers_services_v1_upstream_message_service_proto_init() {
	if File_controller_servers_services_v1_upstream_message_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpstreamMessageRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpstreamMessageResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EchoUpstreamMessageRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EchoUpstreamMessageResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*UpstreamMessageRequest_Ct)(nil),
		(*UpstreamMessageRequest_Pt)(nil),
	}
	file_controller_servers_services_v1_upstream_message_service_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*UpstreamMessageResponse_Ct)(nil),
		(*UpstreamMessageResponse_Pt)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_servers_services_v1_upstream_message_service_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controller_servers_services_v1_upstream_message_service_proto_goTypes,
		DependencyIndexes: file_controller_servers_services_v1_upstream_message_service_proto_depIdxs,
		EnumInfos:         file_controller_servers_services_v1_upstream_message_service_proto_enumTypes,
		MessageInfos:      file_controller_servers_services_v1_upstream_message_service_proto_msgTypes,
	}.Build()
	File_controller_servers_services_v1_upstream_message_service_proto = out.File
	file_controller_servers_services_v1_upstream_message_service_proto_rawDesc = nil
	file_controller_servers_services_v1_upstream_message_service_proto_goTypes = nil
	file_controller_servers_services_v1_upstream_message_service_proto_depIdxs = nil
}
