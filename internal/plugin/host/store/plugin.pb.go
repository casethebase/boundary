// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.15.8
// source: controller/storage/plugin/host/store/v1/plugin.proto

// Package store provides protobufs for storing types in the host package.

package store

import (
	timestamp "github.com/hashicorp/boundary/internal/db/timestamp"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
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

type Plugin struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// public_id is a surrogate key suitable for use in a public API.
	// @inject_tag: `gorm:"primary_key"`
	PublicId string `protobuf:"bytes,10,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty" gorm:"primary_key"`
	// The create_time is set by the database.
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,20,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// The update_time is set by the database.
	// @inject_tag: `gorm:"default:current_timestamp"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,30,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:current_timestamp"`
	// name is optional. If set, it must be unique within scope_id.
	// @inject_tag: `gorm:"default:null"`
	Name string `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty" gorm:"default:null"`
	// description is optional.
	// @inject_tag: `gorm:"default:null"`
	Description string `protobuf:"bytes,50,opt,name=description,proto3" json:"description,omitempty" gorm:"default:null"`
	// The scope_id of the owning scope and must be set.
	// @inject_tag: `gorm:"not_null"`
	ScopeId string `protobuf:"bytes,60,opt,name=scope_id,json=scopeId,proto3" json:"scope_id,omitempty" gorm:"not_null"`
	// @inject_tag: `gorm:"default:null"`
	Version uint32 `protobuf:"varint,70,opt,name=version,proto3" json:"version,omitempty" gorm:"default:null"`
	// plugin_name is required.  The value must be unique across all host plugins
	// @inject_tag: `gorm:"default:null"`
	PluginName string `protobuf:"bytes,80,opt,name=plugin_name,json=pluginName,proto3" json:"plugin_name,omitempty" gorm:"default:null"`
	// id_prefix is required.  The value must be unique across all host plugins
	// @inject_tag: `gorm:"default:null"`
	IdPrefix string `protobuf:"bytes,90,opt,name=id_prefix,json=idPrefix,proto3" json:"id_prefix,omitempty" gorm:"default:null"`
}

func (x *Plugin) Reset() {
	*x = Plugin{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_plugin_host_store_v1_plugin_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Plugin) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Plugin) ProtoMessage() {}

func (x *Plugin) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_plugin_host_store_v1_plugin_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Plugin.ProtoReflect.Descriptor instead.
func (*Plugin) Descriptor() ([]byte, []int) {
	return file_controller_storage_plugin_host_store_v1_plugin_proto_rawDescGZIP(), []int{0}
}

func (x *Plugin) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *Plugin) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *Plugin) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *Plugin) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Plugin) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *Plugin) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *Plugin) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *Plugin) GetPluginName() string {
	if x != nil {
		return x.PluginName
	}
	return ""
}

func (x *Plugin) GetIdPrefix() string {
	if x != nil {
		return x.IdPrefix
	}
	return ""
}

var File_controller_storage_plugin_host_store_v1_plugin_proto protoreflect.FileDescriptor

var file_controller_storage_plugin_host_store_v1_plugin_proto_rawDesc = []byte{
	0x0a, 0x34, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2f, 0x68, 0x6f, 0x73, 0x74,
	0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x27, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x6c, 0x75, 0x67, 0x69,
	0x6e, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x1a,
	0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2f, 0x76, 0x31,
	0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x63, 0x75, 0x73,
	0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9a, 0x03, 0x0a,
	0x06, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x5f, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x49, 0x64, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74,
	0x69, 0x6d, 0x65, 0x18, 0x14, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d,
	0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65,
	0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x24,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x10, 0xc2, 0xdd,
	0x29, 0x0c, 0x0a, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x40, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x32, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1e, 0xc2, 0xdd, 0x29, 0x1a, 0x0a,
	0x0b, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f,
	0x69, 0x64, 0x18, 0x3c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x49,
	0x64, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x46, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x70,
	0x6c, 0x75, 0x67, 0x69, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x50, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0a, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1b, 0x0a, 0x09,
	0x69, 0x64, 0x5f, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x18, 0x5a, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x69, 0x64, 0x50, 0x72, 0x65, 0x66, 0x69, 0x78, 0x42, 0x40, 0x5a, 0x3e, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72,
	0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72,
	0x6e, 0x61, 0x6c, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x2f,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x3b, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_controller_storage_plugin_host_store_v1_plugin_proto_rawDescOnce sync.Once
	file_controller_storage_plugin_host_store_v1_plugin_proto_rawDescData = file_controller_storage_plugin_host_store_v1_plugin_proto_rawDesc
)

func file_controller_storage_plugin_host_store_v1_plugin_proto_rawDescGZIP() []byte {
	file_controller_storage_plugin_host_store_v1_plugin_proto_rawDescOnce.Do(func() {
		file_controller_storage_plugin_host_store_v1_plugin_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_plugin_host_store_v1_plugin_proto_rawDescData)
	})
	return file_controller_storage_plugin_host_store_v1_plugin_proto_rawDescData
}

var file_controller_storage_plugin_host_store_v1_plugin_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_controller_storage_plugin_host_store_v1_plugin_proto_goTypes = []interface{}{
	(*Plugin)(nil),              // 0: controller.storage.plugin.host.store.v1.Plugin
	(*timestamp.Timestamp)(nil), // 1: controller.storage.timestamp.v1.Timestamp
}
var file_controller_storage_plugin_host_store_v1_plugin_proto_depIdxs = []int32{
	1, // 0: controller.storage.plugin.host.store.v1.Plugin.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	1, // 1: controller.storage.plugin.host.store.v1.Plugin.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_controller_storage_plugin_host_store_v1_plugin_proto_init() }
func file_controller_storage_plugin_host_store_v1_plugin_proto_init() {
	if File_controller_storage_plugin_host_store_v1_plugin_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_storage_plugin_host_store_v1_plugin_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Plugin); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_storage_plugin_host_store_v1_plugin_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_plugin_host_store_v1_plugin_proto_goTypes,
		DependencyIndexes: file_controller_storage_plugin_host_store_v1_plugin_proto_depIdxs,
		MessageInfos:      file_controller_storage_plugin_host_store_v1_plugin_proto_msgTypes,
	}.Build()
	File_controller_storage_plugin_host_store_v1_plugin_proto = out.File
	file_controller_storage_plugin_host_store_v1_plugin_proto_rawDesc = nil
	file_controller_storage_plugin_host_store_v1_plugin_proto_goTypes = nil
	file_controller_storage_plugin_host_store_v1_plugin_proto_depIdxs = nil
}
