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

public class PITable {
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

	@SerializedName("CategoryNames")
	private List<String> categoryNames = null;

	@SerializedName("TimeZone")
	private String timeZone = null;

	@SerializedName("ConvertToLocalTime")
	private Boolean convertToLocalTime = null;

	@SerializedName("Links")
	private Map<String, String> links = null;

	public PITable() {
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

	public void setCategoryNames(List<String> categoryNames) { this.categoryNames = categoryNames;}

	public List<String> getCategoryNames() { return this.categoryNames;}

	public void setTimeZone(String timeZone) { this.timeZone = timeZone;}

	public String getTimeZone() { return this.timeZone;}

	public void setConvertToLocalTime(Boolean convertToLocalTime) { this.convertToLocalTime = convertToLocalTime;}

	public Boolean getConvertToLocalTime() { return this.convertToLocalTime;}

	public void setLinks(Map<String, String> links) { this.links = links;}

	public Map<String, String> getLinks() { return this.links;}
}
