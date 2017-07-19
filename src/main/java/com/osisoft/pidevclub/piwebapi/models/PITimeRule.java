/*
 *
 * Copyright 2017 OSIsoft, LLC
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   <http://www.apache.org/licenses/LICENSE-2.0>
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.osisoft.pidevclub.piwebapi.models;

import java.util.Objects;
import com.google.gson.annotations.SerializedName;
import io.swagger.annotations.ApiModelProperty;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import com.osisoft.pidevclub.piwebapi.models.*;

public class PITimeRule {
	@SerializedName("WebId")
	private String webId = null;

	@SerializedName("Id")
	private String id = null;

	@SerializedName("Name")
	private String name = null;

	@SerializedName("Description")
	private String description = null;

	@SerializedName("Path")
	private String path = null;

	@SerializedName("ConfigString")
	private String configString = null;

	@SerializedName("ConfigStringStored")
	private String configStringStored = null;

	@SerializedName("DisplayString")
	private String displayString = null;

	@SerializedName("EditorType")
	private String editorType = null;

	@SerializedName("IsConfigured")
	private Boolean isConfigured = null;

	@SerializedName("IsInitializing")
	private Boolean isInitializing = null;

	@SerializedName("MergeDuplicatedItems")
	private Boolean mergeDuplicatedItems = null;

	@SerializedName("PlugInName")
	private String plugInName = null;

	@SerializedName("Links")
	private Map<String, String> links = null;

	public PITimeRule() {
	}


	public void setWebId(String webId) { this.webId = webId;}

	public String getWebId() { return this.webId;}

	public void setId(String id) { this.id = id;}

	public String getId() { return this.id;}

	public void setName(String name) { this.name = name;}

	public String getName() { return this.name;}

	public void setDescription(String description) { this.description = description;}

	public String getDescription() { return this.description;}

	public void setPath(String path) { this.path = path;}

	public String getPath() { return this.path;}

	public void setConfigString(String configString) { this.configString = configString;}

	public String getConfigString() { return this.configString;}

	public void setConfigStringStored(String configStringStored) { this.configStringStored = configStringStored;}

	public String getConfigStringStored() { return this.configStringStored;}

	public void setDisplayString(String displayString) { this.displayString = displayString;}

	public String getDisplayString() { return this.displayString;}

	public void setEditorType(String editorType) { this.editorType = editorType;}

	public String getEditorType() { return this.editorType;}

	public void setIsConfigured(Boolean isConfigured) { this.isConfigured = isConfigured;}

	public Boolean getIsConfigured() { return this.isConfigured;}

	public void setIsInitializing(Boolean isInitializing) { this.isInitializing = isInitializing;}

	public Boolean getIsInitializing() { return this.isInitializing;}

	public void setMergeDuplicatedItems(Boolean mergeDuplicatedItems) { this.mergeDuplicatedItems = mergeDuplicatedItems;}

	public Boolean getMergeDuplicatedItems() { return this.mergeDuplicatedItems;}

	public void setPlugInName(String plugInName) { this.plugInName = plugInName;}

	public String getPlugInName() { return this.plugInName;}

	public void setLinks(Map<String, String> links) { this.links = links;}

	public Map<String, String> getLinks() { return this.links;}
}
